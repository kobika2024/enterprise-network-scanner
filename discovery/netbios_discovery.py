"""
NetBIOS / SMB Discovery

Phase 1 — NetBIOS Name Service (UDP 137):
    Send NBNS wildcard query → receive computer name

Phase 2 — SMB Negotiate (TCP 445):
    • SMBv1 response  → parse OS major/minor/build from parameter words
    • SMBv2 response  → continue on same socket with SESSION_SETUP +
                        NTLM_NEGOTIATE → parse build from NTLM_CHALLENGE

This correctly handles modern Windows 10 / 11 / Server 2016-2022 which
all respond with SMBv2 and embed the build number inside the NTLM exchange.
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
    # Windows 7 / 8
    7601:  'Windows 7 SP1',
    7600:  'Windows 7',
}


def _build_to_os(major: int, minor: int, build: int) -> tuple:
    """Return (os_version_str, os_family) from Windows version numbers."""
    if build in WINDOWS_BUILD_MAP:
        return WINDOWS_BUILD_MAP[build], 'Windows'
    if major == 10:
        if build >= 22000:
            return f'Windows 11 (Build {build})', 'Windows'
        return f'Windows 10 (Build {build})', 'Windows'
    if major == 6:
        ver_map = {
            3: 'Windows 8.1 / Server 2012 R2',
            2: 'Windows 8 / Server 2012',
            1: 'Windows 7 / Server 2008 R2',
            0: 'Windows Vista / Server 2008',
        }
        return ver_map.get(minor, f'Windows 6.{minor}'), 'Windows'
    if major == 5:
        return 'Windows XP / Server 2003', 'Windows'
    return f'Windows (Build {build})', 'Windows'


# -----------------------------------------------------------------------
# SMBv1 NEGOTIATE packet
# Includes SMBv2 dialect list so the server can upgrade to SMBv2.
# -----------------------------------------------------------------------
_SMB_NEGOTIATE = (
    b'\x00\x00\x00\x54'                    # NetBIOS session header
    b'\xff\x53\x4d\x42'                    # SMB magic
    b'\x72'                                 # Command: Negotiate
    b'\x00\x00\x00\x00'                    # NT Status
    b'\x18'                                 # Flags
    b'\x01\x28'                             # Flags2
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x00'                             # TID
    b'\xff\xfe'                             # PID
    b'\x00\x00'                             # UID
    b'\x00\x00'                             # MID
    b'\x00'                                 # Word Count
    b'\x31\x00'                             # Byte Count = 49
    b'\x02NT LM 0.12\x00'
    b'\x02SMB 2.002\x00'
    b'\x02SMB 2.???\x00'
)

# -----------------------------------------------------------------------
# NTLM NEGOTIATE blob (Type 1)
# NegotiateFlags = 0xe2028233 — bit 25 (0x02000000) = NTLMSSP_NEGOTIATE_VERSION
# is SET, which tells the server to include the OS version in its CHALLENGE.
# -----------------------------------------------------------------------
_NTLM_NEGOTIATE = bytes([
    # Signature "NTLMSSP\0"
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
    # MessageType = 1 (NEGOTIATE)
    0x01, 0x00, 0x00, 0x00,
    # NegotiateFlags (LE) = 0xe2028233
    # Includes UNICODE | OEM | NTLM | ALWAYS_SIGN | VERSION | 128-bit | KEY_EXCH
    0x33, 0x82, 0x02, 0xe2,
    # DomainName fields — empty (Len=0, MaxLen=0, Offset=40)
    0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
    # Workstation fields — empty (Len=0, MaxLen=0, Offset=40)
    0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
    # Version — placeholder (doesn't affect what server returns)
    0x0a, 0x00, 0x61, 0x4e, 0x00, 0x00, 0x00, 0x0f,
])  # 40 bytes total


# -----------------------------------------------------------------------
# SMBv2 helpers
# -----------------------------------------------------------------------

def _build_smb2_session_setup(ntlm_blob: bytes) -> bytes:
    """
    Build a raw SMBv2 SESSION_SETUP packet carrying an NTLM_NEGOTIATE blob.
    Returns the complete bytes to send (including NetBIOS header).
    """
    ntlm_len = len(ntlm_blob)

    # SESSION_SETUP body — 24 fixed bytes
    # SecurityBufferOffset = 64 (SMB2 header) + 24 (body) = 88 = 0x58
    # This is the offset from the start of the SMB2 header.
    sec_offset = 64 + 24  # = 88

    ss_body = bytearray(24)
    struct.pack_into('<H', ss_body, 0,  25)          # StructureSize = 25
    ss_body[2] = 0                                    # Flags
    ss_body[3] = 1                                    # SecurityMode (signing enabled)
    struct.pack_into('<I', ss_body, 4,  0x0000007f)  # Capabilities
    struct.pack_into('<I', ss_body, 8,  0)            # Channel
    struct.pack_into('<H', ss_body, 12, sec_offset)  # SecurityBufferOffset
    struct.pack_into('<H', ss_body, 14, ntlm_len)    # SecurityBufferLength
    # PreviousSessionId (bytes 16–23) = 0 already

    # SMBv2 header — 64 bytes
    smb2_hdr = bytearray(64)
    smb2_hdr[0:4] = b'\xfe\x53\x4d\x42'             # Protocol ID (FE SMB)
    struct.pack_into('<H', smb2_hdr, 4,  64)          # StructureSize
    # CreditCharge, Status, Flags, NextCommand = 0
    struct.pack_into('<H', smb2_hdr, 12, 1)           # Command: SESSION_SETUP = 1
    struct.pack_into('<H', smb2_hdr, 14, 31)          # CreditRequest
    struct.pack_into('<Q', smb2_hdr, 24, 1)           # MessageId = 1
    # ProcessId, TreeId, SessionId, Signature = 0

    payload = bytes(smb2_hdr) + bytes(ss_body) + ntlm_blob

    # NetBIOS session header: 0x00 + 3-byte big-endian length
    nb_hdr = b'\x00' + len(payload).to_bytes(3, 'big')
    return nb_hdr + payload


def _extract_ntlm_challenge_version(data: bytes) -> dict:
    """
    Find NTLMSSP CHALLENGE (Type 2) in raw bytes and extract OS build.

    NTLM Type-2 layout (all offsets from start of NTLMSSP signature):
      0–7   Signature "NTLMSSP\\0"
      8–11  MessageType  (must be 2)
      12–19 TargetNameFields
      20–23 NegotiateFlags
      24–31 ServerChallenge
      32–39 Reserved
      40–47 TargetInfoFields
      48–55 Version (present when NegotiateFlags bit 25 = 0x02000000 is set)
              48    ProductMajorVersion
              49    ProductMinorVersion
              50–51 ProductBuild  (little-endian uint16)
              52–55 Reserved / NTLMRevisionCurrent
    """
    pos = data.find(b'NTLMSSP\x00')
    if pos < 0:
        return {}

    ntlm = data[pos:]
    if len(ntlm) < 56:
        return {}

    msg_type = struct.unpack_from('<I', ntlm, 8)[0]
    if msg_type != 2:          # Must be Type 2 (CHALLENGE)
        return {}

    flags = struct.unpack_from('<I', ntlm, 20)[0]

    # VERSION flag = bit 25 = 0x02000000
    if flags & 0x02000000:
        major = ntlm[48]
        minor = ntlm[49]
        build = struct.unpack_from('<H', ntlm, 50)[0]
        if build > 0:
            os_version, os_family = _build_to_os(major, minor, build)
            return {
                'major': major,
                'minor': minor,
                'build': build,
                'os_version': os_version,
                'os_family': os_family,
            }

    # Server replied but didn't include version (rare)
    return {'smb2': True}


def _smb2_ntlm_on_socket(sock: socket.socket, timeout: float) -> dict:
    """
    On an already-open TCP-445 socket (after SMBv2 NEGOTIATE response),
    send SESSION_SETUP with NTLM_NEGOTIATE and parse the NTLM_CHALLENGE.
    """
    try:
        packet = _build_smb2_session_setup(_NTLM_NEGOTIATE)
        sock.sendall(packet)
        resp = b''
        # Read in chunks — challenge can span multiple TCP segments
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
            if b'NTLMSSP\x00' in resp:
                break
        return _extract_ntlm_challenge_version(resp)
    except Exception:
        return {}


# -----------------------------------------------------------------------
# SMB Negotiate — handles both SMBv1 and SMBv2
# -----------------------------------------------------------------------

def _smb_negotiate(ip: str, timeout: float = 2.0) -> dict:
    """
    Connect TCP 445, send combined SMBv1/SMBv2 NEGOTIATE.

    • SMBv1 response → parse build from parameter words (old Windows)
    • SMBv2 response → continue NTLM handshake on same socket (modern Windows)

    Returns dict: {major, minor, build, os_version, os_family}  or  {}
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 445))
        sock.sendall(_SMB_NEGOTIATE)
        data = sock.recv(4096)
    except Exception:
        if sock:
            try: sock.close()
            except: pass
        return {}

    if len(data) < 8:
        sock.close()
        return {}

    smb_start = 4  # After NetBIOS session header

    # ── SMBv2 response ──────────────────────────────────────────────────
    if data[smb_start:smb_start + 4] == b'\xfe\x53\x4d\x42':
        # Modern Windows — continue on same socket with NTLM handshake
        result = _smb2_ntlm_on_socket(sock, timeout)
        try: sock.close()
        except: pass
        return result

    try: sock.close()
    except: pass

    # ── SMBv1 response ──────────────────────────────────────────────────
    if data[smb_start:smb_start + 4] != b'\xff\x53\x4d\x42':
        return {}

    try:
        # WordCount is at smb_start + 36
        wc_offset = smb_start + 36
        if wc_offset >= len(data):
            return {}
        word_count = data[wc_offset]
        params_start = wc_offset + 1
        byte_count_offset = params_start + (word_count * 2)

        if byte_count_offset + 2 > len(data):
            return {}

        byte_count = struct.unpack_from('<H', data, byte_count_offset)[0]
        strings_start = byte_count_offset + 2

        # OS version bytes at fixed offsets within the SMBv1 NEGOTIATE response
        # Major at smb_start+47, Minor at smb_start+48, Build at smb_start+49 (LE uint16)
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

        # Fallback: parse NativeOS unicode string from the payload
        raw = data[strings_start:strings_start + byte_count]
        native_os = raw.decode('utf-16-le', errors='ignore').split('\x00')[0]
        if native_os:
            return {'os_version': native_os, 'os_family': 'Windows'}

    except Exception:
        pass

    return {}


# -----------------------------------------------------------------------
# NetBIOS Name Service (UDP 137)
# -----------------------------------------------------------------------

def _build_nbns_query() -> bytes:
    """Build a NetBIOS NBSTAT wildcard query packet."""
    return (
        b'\xab\xcd'          # Transaction ID
        b'\x00\x00'          # Flags: query
        b'\x00\x01'          # Questions: 1
        b'\x00\x00'          # Answer RRs
        b'\x00\x00'          # Authority RRs
        b'\x00\x00'          # Additional RRs
        # Encoded name: wildcard '*' (32-byte encoded)
        b'\x20'
        b'\x43\x4b'          # '*' encoded
        b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'
        b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'
        b'\x41\x41\x41\x41'
        b'\x00'
        b'\x00\x21'          # Type: NBSTAT
        b'\x00\x01'          # Class: IN
    )


def _parse_nbns_response(data: bytes) -> str:
    """Extract computer name from NetBIOS NBSTAT response."""
    try:
        if len(data) < 57:
            return ''
        num_names = data[56]
        for i in range(num_names):
            offset = 57 + i * 18
            if offset + 18 > len(data):
                break
            name_bytes = data[offset:offset + 15]
            name_type  = data[offset + 15]
            flags      = struct.unpack_from('>H', data, offset + 16)[0]
            # Type 0x00 = workstation/server name; bit 15 of flags = group name
            if name_type == 0x00 and not (flags & 0x8000):
                name = name_bytes.decode('ascii', errors='ignore').strip()
                if name:
                    return name
    except Exception:
        pass
    return ''


# -----------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------

def netbios_scan(ip: str, timeout: float = 1.5) -> dict:
    """
    Run NetBIOS (UDP 137) + SMB negotiate (TCP 445) against a single IP.

    Returns:
        {
          'name':           'COMPUTER-NAME',   # from NetBIOS, or None
          'smb_os_version': 'Windows 11 22H2', # from SMB/NTLM, or None
          'smb_os_family':  'Windows',          # or None
          'smb_build':      '22621',            # str build number, or None
        }
    """
    result = {
        'name':           None,
        'smb_os_version': None,
        'smb_os_family':  None,
        'smb_build':      None,
    }

    # ── Phase 1: NetBIOS UDP 137 ────────────────────────────────────────
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

    # ── Phase 2: SMB TCP 445 (SMBv1 + SMBv2 + NTLM) ────────────────────
    smb = _smb_negotiate(ip, timeout=timeout)
    if smb:
        result['smb_os_version'] = smb.get('os_version')
        result['smb_os_family']  = smb.get('os_family')
        build = smb.get('build')
        if build:
            result['smb_build'] = str(build)

    return result
