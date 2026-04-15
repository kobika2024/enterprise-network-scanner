"""
NetBIOS / SMB Discovery

Phase 1 — NetBIOS Name Service (UDP 137):
    Send NBNS wildcard query → receive computer name

Phase 2 — SMB Negotiate (TCP 445):
    Send SMBv1 NEGOTIATE → parse Windows build number from response
    Map build → friendly OS version string
"""
import socket
import struct
import re

# -----------------------------------------------------------------------
# Windows build → friendly name mapping
# -----------------------------------------------------------------------
WINDOWS_BUILD_MAP = {
    # Windows 11
    26100: 'Windows 11 24H2',
    22631: 'Windows 11 23H2',
    22621: 'Windows 11 22H2',
    22000: 'Windows 11 21H2',
    # Windows 10
    19045: 'Windows 10 22H2',
    19044: 'Windows 10 21H2',
    19043: 'Windows 10 21H1',
    19042: 'Windows 10 20H2',
    19041: 'Windows 10 2004',
    18363: 'Windows 10 1909',
    18362: 'Windows 10 1903',
    17763: 'Windows 10 1809',
    17134: 'Windows 10 1803',
    16299: 'Windows 10 1709',
    15063: 'Windows 10 1703',
    14393: 'Windows 10 1607',
    10586: 'Windows 10 1511',
    10240: 'Windows 10 1507',
    # Windows Server
    20348: 'Windows Server 2022',
    17763: 'Windows Server 2019',
    14393: 'Windows Server 2016',
    9600:  'Windows Server 2012 R2',
    9200:  'Windows Server 2012',
    7601:  'Windows Server 2008 R2',
    6002:  'Windows Server 2008',
    # Windows 7 / 8 / 8.1
    7601:  'Windows 7 SP1',
    7600:  'Windows 7',
    9600:  'Windows 8.1',
    9200:  'Windows 8',
}


def _build_to_os(major: int, minor: int, build: int) -> tuple:
    """Return (os_version_str, os_family) from version numbers."""
    # Use build map first
    if build in WINDOWS_BUILD_MAP:
        return WINDOWS_BUILD_MAP[build], 'Windows'

    # Fallback to major.minor
    if major == 10:
        if minor == 0 and build >= 20000:
            return f'Windows 11 (Build {build})', 'Windows'
        return f'Windows 10 (Build {build})', 'Windows'
    if major == 6:
        ver_map = {3: 'Windows 8.1 / Server 2012 R2',
                   2: 'Windows 8 / Server 2012',
                   1: 'Windows 7 / Server 2008 R2',
                   0: 'Windows Vista / Server 2008'}
        return ver_map.get(minor, f'Windows 6.{minor}'), 'Windows'
    if major == 5:
        return 'Windows XP / Server 2003', 'Windows'

    return f'Windows (Build {build})', 'Windows'


# -----------------------------------------------------------------------
# SMBv1 NEGOTIATE packet (raw bytes — constant)
# -----------------------------------------------------------------------
# This packet negotiates both SMBv1 "NT LM 0.12" and SMBv2 dialects.
# The server's response contains OS version info in the SMBv1 path.
_SMB_NEGOTIATE = (
    b'\x00\x00\x00\x54'                    # NetBIOS session header (length=84)
    b'\xff\x53\x4d\x42'                    # SMB magic
    b'\x72'                                 # Command: Negotiate
    b'\x00\x00\x00\x00'                    # NT Status
    b'\x18'                                 # Flags
    b'\x01\x28'                             # Flags2
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # padding
    b'\x00\x00'                             # TID
    b'\xff\xfe'                             # PID
    b'\x00\x00'                             # UID
    b'\x00\x00'                             # MID
    b'\x00'                                 # Word Count
    b'\x31\x00'                             # Byte Count = 49
    b'\x02NT LM 0.12\x00'                  # Dialect 1
    b'\x02SMB 2.002\x00'                   # Dialect 2
    b'\x02SMB 2.???\x00'                   # Dialect 3
)


def _smb_negotiate(ip: str, timeout: float = 2.0) -> dict:
    """
    Connect to TCP 445 and send SMBv1 NEGOTIATE.
    Parse response to extract Windows OS version + build.

    Returns dict with keys: major, minor, build, os_version, os_family
    or empty dict on failure.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, 445))
            s.sendall(_SMB_NEGOTIATE)
            data = s.recv(4096)
    except Exception:
        return {}

    if len(data) < 60:
        return {}

    # SMBv1 response starts with NetBIOS header (4 bytes) + SMB header
    # In the NEGOTIATE response, version info is at specific offsets
    # relative to the start of the SMB header (byte 4)
    smb_start = 4  # after NetBIOS session header

    # Verify it's an SMB response
    if data[smb_start:smb_start+4] != b'\xff\x53\x4d\x42':
        # Might be SMBv2 — SMBv2 negotiate response starts with \xfe\x53\x4d\x42
        if data[smb_start:smb_start+4] == b'\xfe\x53\x4d\x42':
            # Server upgraded to SMBv2 — OS version in NEGOTIATE context
            # SMBv2 DialectRevision at offset 4+36 (bytes 40-41)
            # No OS version in SMBv2 NEGOTIATE — just record SMB2 capability
            return {'smb2': True}
        return {}

    # SMBv1 Negotiate response layout:
    # 4 (NetBIOS) + 32 (SMB header) + 1 (WordCount) + WordCount*2 bytes (params)
    # After params: 2-byte ByteCount, then NativeOS string
    # OS version bytes: offsets within the parameter words
    # Standard location for OS version in NEGOTIATE response:
    # Offset from SMB header start: 47 (major), 48 (minor), 49-50 (build LE)
    try:
        base = smb_start + 45  # skip SMB header (32) + command (1) + status (4) + flags (1+2) + ...
        # More reliable: search for version in the negotiate response word area
        # The word count is at smb_start + 36
        wc_offset = smb_start + 36
        word_count = data[wc_offset]
        params_start = wc_offset + 1

        # OS version is typically in SecurityMode word area
        # For NT NEGOTIATE, the structure is well-defined:
        # Parameters (WC*2 bytes) then ByteCount then strings
        byte_count_offset = params_start + (word_count * 2)
        if byte_count_offset + 2 > len(data):
            return {}

        byte_count = struct.unpack_from('<H', data, byte_count_offset)[0]
        strings_start = byte_count_offset + 2

        # NativeOS is the first null-terminated string after ByteCount
        raw_strings = data[strings_start:strings_start + byte_count]

        # Try to extract version from response bytes at fixed offsets
        # SMBv1 NEGOTIATE response: OS major at offset smb_start+47
        if len(data) > smb_start + 51:
            major = data[smb_start + 47]
            minor = data[smb_start + 48]
            build = struct.unpack_from('<H', data, smb_start + 49)[0]

            if major > 0 or build > 0:
                os_version, os_family = _build_to_os(major, minor, build)
                return {
                    'major': major,
                    'minor': minor,
                    'build': build,
                    'os_version': os_version,
                    'os_family': os_family,
                }

        # Fallback: parse NativeOS unicode string
        try:
            native_os = raw_strings.decode('utf-16-le', errors='ignore').split('\x00')[0]
            if native_os:
                return {'os_version': native_os, 'os_family': 'Windows'}
        except Exception:
            pass

    except Exception:
        pass

    return {}


# -----------------------------------------------------------------------
# NetBIOS Name Service (UDP 137)
# -----------------------------------------------------------------------

def _build_nbns_query() -> bytes:
    """Build a NetBIOS Name Service wildcard query packet."""
    transaction_id = b'\xab\xcd'
    flags = b'\x00\x00'           # Query, non-recursive
    questions = b'\x00\x01'       # 1 question
    answer_rrs = b'\x00\x00'
    authority_rrs = b'\x00\x00'
    additional_rrs = b'\x00\x00'

    # Encoded name: '*' (0x2A) → 'CA' (each nibble + 0x41), padded to 16 chars
    # '*' = 0x2A → high nibble 2 → 'C' (0x43), low nibble A → 'K' (0x4B)
    # Remaining 15 bytes are spaces (0x20 → 'CA') padded
    # Standard: wildcard = CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (32 bytes)
    encoded_name = (
        b'\x20'                    # length = 32
        b'\x43\x4b'               # '*' encoded
        b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'  # 14 x ' '
        b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'  # 14 x ' '
        b'\x41\x41\x41\x41'       # 4 x ' '
        b'\x00'                    # null terminator
    )
    qtype = b'\x00\x21'           # NBSTAT
    qclass = b'\x00\x01'          # IN

    return (transaction_id + flags + questions + answer_rrs +
            authority_rrs + additional_rrs + encoded_name + qtype + qclass)


def _parse_nbns_response(data: bytes) -> str:
    """Extract the computer name from a NetBIOS NBSTAT response."""
    try:
        if len(data) < 57:
            return ''
        # Number of names is at offset 56
        num_names = data[56]
        for i in range(num_names):
            offset = 57 + i * 18
            if offset + 18 > len(data):
                break
            name_bytes = data[offset:offset + 15]
            name_type = data[offset + 15]
            flags = struct.unpack_from('>H', data, offset + 16)[0]
            # Type 0x00 = workstation/server name, not a group name
            if name_type == 0x00 and not (flags & 0x8000):
                name = name_bytes.decode('ascii', errors='ignore').strip()
                if name:
                    return name
    except Exception:
        pass
    return ''


def netbios_scan(ip: str, timeout: float = 1.5) -> dict:
    """
    Run NetBIOS (UDP 137) + SMB negotiate (TCP 445) against a single IP.

    Returns:
        {
          'name': 'COMPUTER-NAME',    # from NetBIOS, or None
          'smb_os_version': '...',    # from SMB negotiate, or None
          'smb_os_family': 'Windows', # or None
          'smb_build': '22621',       # str build number, or None
        }
    """
    result = {
        'name': None,
        'smb_os_version': None,
        'smb_os_family': None,
        'smb_build': None,
    }

    # --- Phase 1: NetBIOS UDP 137 ---
    try:
        packet = _build_nbns_query()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (ip, 137))
            data, _ = s.recvfrom(1024)
            name = _parse_nbns_response(data)
            if name:
                result['name'] = name
    except Exception:
        pass

    # --- Phase 2: SMB TCP 445 ---
    smb = _smb_negotiate(ip, timeout=timeout)
    if smb:
        result['smb_os_version'] = smb.get('os_version')
        result['smb_os_family'] = smb.get('os_family')
        build = smb.get('build')
        if build:
            result['smb_build'] = str(build)

    return result
