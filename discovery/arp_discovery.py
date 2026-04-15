"""
ARP Discovery — finds all live hosts on the local subnet using:
  1. Existing ARP cache (arp -a) before probing
  2. UDP probe trick: sending empty datagrams forces the kernel to resolve
     MACs via ARP, then reading the refreshed cache
No Npcap / scapy required.
"""
import re
import socket
import subprocess
import ipaddress
import concurrent.futures
import platform

# -----------------------------------------------------------------------
# Minimal OUI vendor table (top vendors for classification purposes)
# Keys: first 3 bytes uppercase, no separators  e.g. "001C7F"
# -----------------------------------------------------------------------
OUI_TABLE = {
    # VMware
    '005056': 'VMware', '000C29': 'VMware', '000569': 'VMware',
    # VirtualBox
    '080027': 'VirtualBox',
    # Hyper-V
    '00155D': 'Microsoft Hyper-V',
    # QEMU/KVM
    '525400': 'QEMU/KVM',
    # Cisco
    '000142': 'Cisco', '000143': 'Cisco', '000B45': 'Cisco',
    '001120': 'Cisco', '0014A9': 'Cisco', '001C57': 'Cisco',
    '001D45': 'Cisco', '001E13': 'Cisco', '001E14': 'Cisco',
    '0021A0': 'Cisco', '0023AC': 'Cisco', '002564': 'Cisco',
    '002590': 'Cisco', '0026CB': 'Cisco', '001517': 'Cisco',
    # HP / HPE
    '001083': 'HP', '0017A4': 'HP', '001CC4': 'HP',
    '002170': 'HP', '3C4A92': 'HP', 'B499BA': 'HPE',
    # Dell
    '001372': 'Dell', '0021F6': 'Dell', '14187B': 'Dell',
    'F48E38': 'Dell', 'F0761C': 'Dell',
    # Lenovo
    '4CE17A': 'Lenovo', '98FA9B': 'Lenovo', 'D4F557': 'Lenovo',
    # Juniper
    '0019E2': 'Juniper', '002197': 'Juniper', '0024DC': 'Juniper',
    # MikroTik
    '4C5E0C': 'MikroTik', '6C3B6B': 'MikroTik', 'B8690E': 'MikroTik',
    'D4CA6D': 'MikroTik', '18FD74': 'MikroTik', 'CC2DE0': 'MikroTik',
    # Ubiquiti
    '00272C': 'Ubiquiti', '0418D6': 'Ubiquiti', '24A43C': 'Ubiquiti',
    '68722D': 'Ubiquiti', '802AA8': 'Ubiquiti', 'DC9FDB': 'Ubiquiti',
    # Raspberry Pi
    'B827EB': 'Raspberry Pi', 'DC:A6:32': 'Raspberry Pi', 'E4:5F:01': 'Raspberry Pi',
    # Apple
    '000A27': 'Apple', '000A95': 'Apple', '001124': 'Apple',
    '001451': 'Apple', '001CB3': 'Apple', '0050E4': 'Apple',
    # Intel (common NICs)
    '001517': 'Intel', '002219': 'Intel', '8086F2': 'Intel',
    # Realtek
    '00E04C': 'Realtek',
    # Printer vendors
    '000748': 'Brother', '001BA9': 'Canon', '001871': 'Epson',
    '000AE4': 'HP Printer', '1C7EE5': 'HP Printer', '708966': 'Lexmark',
    # Netgear
    '00095B': 'Netgear', '001E2A': 'Netgear', '20E52A': 'Netgear',
    # TP-Link
    '50C7BF': 'TP-Link', '6C5AB0': 'TP-Link', '98DABC': 'TP-Link',
}

# Vendor → asset_type hint
VENDOR_TYPE_MAP = {
    'VMware': 'VM',
    'VirtualBox': 'VM',
    'Microsoft Hyper-V': 'VM',
    'QEMU/KVM': 'VM',
    'Cisco': 'Network Device',
    'Juniper': 'Network Device',
    'MikroTik': 'Network Device',
    'Ubiquiti': 'Network Device',
    'Netgear': 'Network Device',
    'TP-Link': 'Network Device',
    'Brother': 'Printer',
    'Canon': 'Printer',
    'Epson': 'Printer',
    'HP Printer': 'Printer',
    'Lexmark': 'Printer',
}


def _normalize_mac(raw: str) -> str:
    """Normalize MAC to uppercase colon-separated format: AA:BB:CC:DD:EE:FF."""
    cleaned = re.sub(r'[^0-9a-fA-F]', '', raw)
    if len(cleaned) != 12:
        return raw.upper()
    return ':'.join(cleaned[i:i+2].upper() for i in range(0, 12, 2))


def _oui_lookup(mac: str) -> str:
    """Return vendor name from MAC OUI prefix."""
    key = mac.replace(':', '').replace('-', '')[:6].upper()
    return OUI_TABLE.get(key, '')


def _vendor_to_type(vendor: str) -> str:
    """Suggest asset_type based on MAC vendor."""
    return VENDOR_TYPE_MAP.get(vendor, '')


def _parse_arp_output(output: str) -> dict:
    """
    Parse 'arp -a' output on Windows and Linux.
    Returns {ip: {mac, vendor, type_hint}}
    """
    results = {}
    is_windows = platform.system() == 'Windows'

    if is_windows:
        # Windows: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
        pattern = re.compile(
            r'(\d{1,3}(?:\.\d{1,3}){3})\s+([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}'
            r'[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})\s+(dynamic|static)',
            re.IGNORECASE
        )
    else:
        # Linux: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
        pattern = re.compile(
            r'\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([\da-fA-F]{2}[:-][\da-fA-F]{2}'
            r'[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})',
            re.IGNORECASE
        )

    for m in pattern.finditer(output):
        ip = m.group(1)
        raw_mac = m.group(2)
        mac = _normalize_mac(raw_mac)
        vendor = _oui_lookup(mac)
        results[ip] = {
            'mac': mac,
            'vendor': vendor,
            'type_hint': _vendor_to_type(vendor),
        }
    return results


def _read_arp_cache() -> dict:
    """Read the current ARP cache via 'arp -a'."""
    try:
        result = subprocess.run(
            ['arp', '-a'],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return _parse_arp_output(result.stdout)
    except Exception:
        return {}


def _udp_probe(ip: str, port: int = 9) -> None:
    """
    Send a zero-byte UDP datagram to force the OS to resolve the MAC
    via ARP. No response is expected (port 9 = discard).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.1)
            s.sendto(b'', (ip, port))
    except Exception:
        pass


def _probe_subnet(hosts: list, max_workers: int = 150) -> None:
    """Fire UDP probes at all hosts simultaneously."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(ex.map(_udp_probe, hosts))


# -----------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------

def arp_sweep(target: str) -> dict:
    """
    Perform ARP discovery on the target CIDR/IP range.

    Returns:
        {ip_str: {'mac': '...', 'vendor': '...', 'type_hint': '...'}}
    """
    # Parse target into list of host IPs
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(h) for h in network.hosts()]
    except ValueError:
        hosts = [target]

    # Step 1: snapshot existing cache
    initial = _read_arp_cache()

    # Step 2: probe all hosts to populate ARP cache
    _probe_subnet(hosts)

    # Step 3: short wait for ARP responses to settle
    import time
    time.sleep(1.5)

    # Step 4: read refreshed cache
    refreshed = _read_arp_cache()

    # Merge (refreshed overrides initial)
    merged = {**initial, **refreshed}

    # Filter to only IPs in our target subnet
    target_set = set(hosts)
    return {ip: data for ip, data in merged.items() if ip in target_set}
