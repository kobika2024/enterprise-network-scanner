"""
OS Fingerprinting — layered OS detection from multiple data sources.

Priority (highest confidence first):
  1. SMB Negotiate response       → HIGH confidence
  2. SSH banner parsing           → HIGH confidence
  3. SNMP sysDescr parsing        → HIGH confidence
  4. HTTP Server / X-Powered-By   → MEDIUM confidence
  5. TTL analysis from ping       → LOW confidence
"""
import re
import subprocess
import platform


# -----------------------------------------------------------------------
# SSH banner → OS mapping
# -----------------------------------------------------------------------
SSH_OS_PATTERNS = [
    # Windows
    (r'OpenSSH_for_Windows',          'Windows',        'Windows (SSH)',     'HIGH'),
    (r'OpenSSH_[\d.]+p\d+ Ubuntu',   'Linux',          None,                'HIGH'),
    (r'OpenSSH_[\d.]+p\d+ Debian',   'Linux',          None,                'HIGH'),
    (r'OpenSSH_[\d.]+p\d+ CentOS',   'Linux',          None,                'HIGH'),
    (r'OpenSSH_[\d.]+p\d+ Fedora',   'Linux',          None,                'HIGH'),
    (r'OpenSSH_[\d.]+p\d+ RHEL',     'Linux',          None,                'HIGH'),
    # General Ubuntu
    (r'Ubuntu-(\d+ubuntu[\d.]+)',     'Linux',          None,                'HIGH'),
    # Cisco
    (r'SSH-2\.0-Cisco',               'Network Device', 'Cisco IOS',         'HIGH'),
    (r'SSH-1\.99-Cisco',              'Network Device', 'Cisco IOS',         'HIGH'),
    # MikroTik
    (r'ROSSSH',                       'Network Device', 'MikroTik RouterOS', 'HIGH'),
    # Juniper
    (r'SSH-2\.0-OpenSSH.*Juniper',   'Network Device', 'Juniper JunOS',     'HIGH'),
    # FreeBSD
    (r'FreeBSD',                      'BSD',            None,                'HIGH'),
    # Generic Linux
    (r'OpenSSH',                      'Linux',          None,                'LOW'),
]

# -----------------------------------------------------------------------
# HTTP Server header → OS mapping
# -----------------------------------------------------------------------
HTTP_OS_PATTERNS = [
    (r'Microsoft-IIS/(\d+)',          'Windows', 'Windows (IIS {0})',  'MEDIUM'),
    (r'Microsoft-HTTPAPI',            'Windows', 'Windows',            'MEDIUM'),
    (r'ASP\.NET',                     'Windows', 'Windows',            'MEDIUM'),
    (r'Apache.*Ubuntu',               'Linux',   'Ubuntu',             'MEDIUM'),
    (r'Apache.*Debian',               'Linux',   'Debian',             'MEDIUM'),
    (r'Apache.*CentOS',               'Linux',   'CentOS',             'MEDIUM'),
    (r'Apache.*Red Hat',              'Linux',   'Red Hat',            'MEDIUM'),
    (r'nginx',                        'Linux',   None,                 'LOW'),
    (r'Apache',                       'Linux',   None,                 'LOW'),
]

# -----------------------------------------------------------------------
# SNMP sysDescr → OS mapping
# -----------------------------------------------------------------------
SNMP_OS_PATTERNS = [
    # Windows
    (r'Windows.*?(\d+\.\d+\.\d+\.\d+)',  'Windows', None, 'HIGH'),
    (r'Windows Server (\d{4})',           'Windows', None, 'HIGH'),
    (r'Windows (\d+)',                    'Windows', None, 'HIGH'),
    # Linux distributions
    (r'Linux.*Ubuntu',                    'Linux',   None, 'HIGH'),
    (r'Linux.*Debian',                    'Linux',   None, 'HIGH'),
    (r'Linux.*CentOS',                    'Linux',   None, 'HIGH'),
    (r'Linux.*Red Hat',                   'Linux',   None, 'HIGH'),
    (r'Linux.*Fedora',                    'Linux',   None, 'HIGH'),
    (r'Linux',                            'Linux',   None, 'MEDIUM'),
    # Network devices
    (r'Cisco IOS',                        'Network Device', 'Cisco IOS',          'HIGH'),
    (r'IOS-XE',                           'Network Device', 'Cisco IOS-XE',       'HIGH'),
    (r'IOS-XR',                           'Network Device', 'Cisco IOS-XR',       'HIGH'),
    (r'Junos',                            'Network Device', 'Juniper JunOS',       'HIGH'),
    (r'RouterOS',                         'Network Device', 'MikroTik RouterOS',   'HIGH'),
    (r'VyOS',                             'Network Device', 'VyOS',               'HIGH'),
    (r'FortiOS',                          'Network Device', 'Fortinet FortiOS',    'HIGH'),
    (r'Palo Alto',                        'Network Device', 'Palo Alto PAN-OS',    'HIGH'),
    (r'pfSense',                          'Network Device', 'pfSense',             'HIGH'),
    # ESXi / VMware
    (r'VMware ESXi',                      'Hypervisor',     None,                  'HIGH'),
    (r'ESXi',                             'Hypervisor',     'VMware ESXi',         'HIGH'),
    # Printers
    (r'HP LaserJet',                      'Printer',        None,                  'HIGH'),
    (r'RICOH',                            'Printer',        None,                  'HIGH'),
    (r'Xerox',                            'Printer',        None,                  'HIGH'),
    (r'Canon',                            'Printer',        None,                  'HIGH'),
]

# -----------------------------------------------------------------------
# TTL → OS guess
# -----------------------------------------------------------------------
def _ttl_to_os(ttl: int) -> tuple:
    """
    Guess OS from observed TTL value.
    Returns (os_family, confidence)
    """
    if ttl is None:
        return None, None
    if 113 <= ttl <= 128:
        return 'Windows', 'LOW'
    if 49 <= ttl <= 64:
        return 'Linux', 'LOW'
    if 200 <= ttl <= 255:
        return 'Network Device', 'LOW'
    if 100 <= ttl <= 112:
        return 'Linux', 'LOW'
    if 65 <= ttl <= 99:
        return 'Linux', 'LOW'
    return None, None


# -----------------------------------------------------------------------
# SSH banner parsing
# -----------------------------------------------------------------------
def _parse_ssh_banner(banner: str) -> tuple:
    """
    Returns (os_family, os_version, confidence) from SSH version string.
    """
    if not banner:
        return None, None, None

    for pattern, family, version_tpl, confidence in SSH_OS_PATTERNS:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            version = None
            if version_tpl:
                try:
                    version = version_tpl.format(*m.groups())
                except Exception:
                    version = version_tpl

            # Try to extract distro version from Ubuntu pattern
            if family == 'Linux':
                ubuntu_m = re.search(r'Ubuntu-(\d+)ubuntu', banner)
                if ubuntu_m:
                    ver_num = int(ubuntu_m.group(1))
                    # Ubuntu package version → release mapping (approximate)
                    if ver_num >= 100:
                        version = f'Ubuntu {ver_num // 4 + 10}.04'
                    else:
                        version = f'Ubuntu (pkg {ver_num})'

                debian_m = re.search(r'Debian-(\S+)', banner)
                if debian_m:
                    version = f'Debian ({debian_m.group(1)})'

            return family, version, confidence

    return None, None, None


# -----------------------------------------------------------------------
# HTTP Server header parsing
# -----------------------------------------------------------------------
def _parse_http_banner(server_header: str) -> tuple:
    """Returns (os_family, os_version, confidence)."""
    if not server_header:
        return None, None, None

    for pattern, family, version_tpl, confidence in HTTP_OS_PATTERNS:
        m = re.search(pattern, server_header, re.IGNORECASE)
        if m:
            version = None
            if version_tpl:
                try:
                    version = version_tpl.format(*m.groups())
                except Exception:
                    version = version_tpl
            return family, version, confidence

    return None, None, None


# -----------------------------------------------------------------------
# SNMP sysDescr parsing
# -----------------------------------------------------------------------
def _parse_snmp_sysdesc(sysdesc: str) -> tuple:
    """Returns (os_family, os_version, confidence)."""
    if not sysdesc:
        return None, None, None

    for pattern, family, version, confidence in SNMP_OS_PATTERNS:
        m = re.search(pattern, sysdesc, re.IGNORECASE)
        if m:
            # For Windows, try to extract the version string from context
            if family == 'Windows' and not version:
                ws_match = re.search(r'Windows[^\x00-\x1f]+', sysdesc)
                if ws_match:
                    version = ws_match.group(0).strip()[:80]
            # For Linux, try to extract version
            if family == 'Linux' and not version:
                lx_match = re.search(r'(Ubuntu|Debian|CentOS|Red Hat|Fedora|RHEL)[^\x00-\x1f]*',
                                     sysdesc, re.IGNORECASE)
                if lx_match:
                    version = lx_match.group(0).strip()[:80]
            return family, version, confidence

    return None, None, None


# -----------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------

CONFIDENCE_RANK = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, None: 0}


def determine_os(asset_data: dict) -> tuple:
    """
    Determine best OS from all available data sources.

    Args:
        asset_data: dict with keys:
            smb_os_version, smb_os_family  (from netbios_discovery)
            ssh_banner                      (from scanner.py banner)
            http_server_header              (from scanner.py banner)
            snmp_sysdesc                    (from snmp_discovery)
            ttl                             (from ping)

    Returns:
        (os_family, os_version, os_confidence, os_method)
    """
    candidates = []

    # 1. SMB negotiate (HIGH)
    smb_fam = asset_data.get('smb_os_family')
    smb_ver = asset_data.get('smb_os_version')
    if smb_fam:
        candidates.append((smb_fam, smb_ver, 'HIGH', 'SMB-Negotiate'))

    # 2. SSH banner (HIGH)
    ssh_fam, ssh_ver, ssh_conf = _parse_ssh_banner(asset_data.get('ssh_banner', ''))
    if ssh_fam:
        candidates.append((ssh_fam, ssh_ver, ssh_conf, 'SSH-Banner'))

    # 3. SNMP sysDescr (HIGH for known patterns)
    snmp_fam, snmp_ver, snmp_conf = _parse_snmp_sysdesc(asset_data.get('snmp_sysdesc', ''))
    if snmp_fam:
        candidates.append((snmp_fam, snmp_ver, snmp_conf, 'SNMP-sysDescr'))

    # 4. HTTP Server header (MEDIUM)
    http_fam, http_ver, http_conf = _parse_http_banner(asset_data.get('http_server_header', ''))
    if http_fam:
        candidates.append((http_fam, http_ver, http_conf, 'HTTP-Server'))

    # 5. TTL (LOW)
    ttl_fam, ttl_conf = _ttl_to_os(asset_data.get('ttl'))
    if ttl_fam:
        candidates.append((ttl_fam, None, ttl_conf, 'TTL'))

    if not candidates:
        return None, None, None, None

    # Pick highest-confidence candidate
    best = max(candidates, key=lambda c: CONFIDENCE_RANK.get(c[2], 0))
    return best  # (os_family, os_version, os_confidence, os_method)


def classify_asset(asset_data: dict) -> str:
    """
    Classify asset type from all available signals.

    Returns one of:
      Server, Workstation, VM, Container, Network Device, Printer, Hypervisor, Unknown
    """
    # MAC vendor hint is the strongest signal for VMs / Network devices
    type_hint = asset_data.get('mac_type_hint', '')
    if type_hint:
        return type_hint

    os_family = asset_data.get('os_family', '')
    snmp_desc = asset_data.get('snmp_sysdesc', '') or ''
    open_ports = asset_data.get('open_ports', [])
    is_docker = asset_data.get('is_docker_host', False)

    port_numbers = {p.get('port', 0) for p in open_ports}

    if is_docker:
        return 'Container Host'

    if os_family == 'Hypervisor':
        return 'Hypervisor'

    if os_family == 'Network Device':
        # Refine: router vs switch vs firewall
        if any(p in port_numbers for p in [179]):  # BGP
            return 'Router'
        if any(p in port_numbers for p in [443, 4443]) and 'FortiGate' in snmp_desc:
            return 'Firewall'
        return 'Network Device'

    if os_family == 'Printer':
        return 'Printer'

    if os_family in ('Windows', 'Linux', 'BSD', 'macOS'):
        # Check for server indicators
        server_ports = {21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 636,
                        1433, 1521, 3306, 5432, 3389, 5900, 5985, 5986, 8080, 8443}
        matched_server_ports = port_numbers & server_ports

        if len(matched_server_ports) >= 3:
            return 'Server'

        # Windows: RDP open but few other services → Workstation
        if os_family == 'Windows' and 3389 in port_numbers and len(port_numbers) <= 4:
            return 'Workstation'

        # Windows domain controller indicators
        if {88, 389, 445, 636, 3268} & port_numbers:
            return 'Domain Controller'

        # Database server
        if {1433, 1521, 3306, 5432, 27017} & port_numbers:
            return 'Database Server'

        # Web server
        if {80, 443} & port_numbers and len(matched_server_ports) <= 3:
            return 'Web Server'

        if len(port_numbers) >= 5:
            return 'Server'

        return 'Workstation' if os_family == 'Windows' else 'Server'

    return 'Unknown'
