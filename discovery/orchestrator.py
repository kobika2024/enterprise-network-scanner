"""
Discovery Orchestrator — runs all discovery modules in parallel and
merges results into a unified list of Asset objects.

Pipeline:
  Phase 1 (network-wide, fast): ARP + DNS sweep + ICMP ping
  Phase 2 (per-host, parallel): TCP scan + NetBIOS + SNMP + Docker
  Phase 3 (enrichment):         OS fingerprint + asset classification + hostname selection
"""
import concurrent.futures
import ipaddress
import subprocess
import platform
import re
import sys
import os
from datetime import datetime

# Add parent directory to path so imports work when run standalone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.asset import Asset
from discovery.arp_discovery import arp_sweep
from discovery.dns_sweep import dns_sweep
from discovery.netbios_discovery import netbios_scan
from discovery.snmp_discovery import snmp_scan
from discovery.docker_discovery import docker_scan
from discovery.os_fingerprint import determine_os, classify_asset

# Import TCP scanner from existing scanner.py
try:
    from scanner import scan_host, ping_host
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False


# -----------------------------------------------------------------------
# ICMP ping sweep (uses existing scanner.py or raw subprocess)
# -----------------------------------------------------------------------

def _ping(ip: str) -> tuple:
    """Returns (ip, alive, ttl)."""
    is_windows = platform.system() == 'Windows'
    try:
        if is_windows:
            cmd = ['ping', '-n', '1', '-w', '1000', ip]
        else:
            cmd = ['ping', '-c', '1', '-W', '1', ip]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        output = result.stdout + result.stderr
        alive = result.returncode == 0

        ttl = None
        ttl_match = re.search(r'TTL[=:](\d+)', output, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))

        return ip, alive, ttl
    except Exception:
        return ip, False, None


def icmp_sweep(target: str, max_workers: int = 100) -> dict:
    """
    Ping all hosts in target subnet.
    Returns {ip: {'alive': bool, 'ttl': int|None}}
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(h) for h in network.hosts()]
    except ValueError:
        hosts = [target]

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for ip, alive, ttl in ex.map(_ping, hosts):
            results[ip] = {'alive': alive, 'ttl': ttl}

    return results


# -----------------------------------------------------------------------
# Per-host TCP scan wrapper
# -----------------------------------------------------------------------

def _tcp_scan_host(ip: str, ports: list, timeout: float,
                   progress_cb=None) -> dict:
    """
    Wrap existing scanner.py scan_host() or do a minimal TCP scan.
    Returns {'alive': bool, 'ports': [...], 'ssh_banner': ..., 'http_server_header': ...}
    """
    if SCANNER_AVAILABLE:
        try:
            result = scan_host(ip, ports=ports, timeout=timeout)
            # Extract SSH banner and HTTP Server header from results
            ssh_banner = ''
            http_server = ''
            for port_info in result.get('ports', []):
                banner = port_info.get('banner', '')
                port_num = port_info.get('port', 0)
                if port_num == 22 and 'SSH' in banner:
                    ssh_banner = banner
                if port_num in (80, 443, 8080, 8443):
                    if 'Server:' in banner:
                        m = re.search(r'Server:\s*(.+?)[\r\n]', banner)
                        if m:
                            http_server = m.group(1).strip()
            return {
                'alive': result.get('alive', False),
                'ports': result.get('ports', []),
                'ssh_banner': ssh_banner,
                'http_server_header': http_server,
            }
        except Exception:
            pass

    return {'alive': False, 'ports': [], 'ssh_banner': '', 'http_server_header': ''}


# -----------------------------------------------------------------------
# Per-host full discovery
# -----------------------------------------------------------------------

def _discover_host(ip: str, options: dict, scan_id: str,
                   arp_data: dict, dns_data: dict, icmp_data: dict) -> Asset:
    """
    Run all per-host discovery modules in parallel and return an Asset.
    """
    asset = Asset(ip=ip, scan_id=scan_id)

    # Pre-populate from Phase 1 data
    arp_info = arp_data.get(ip, {})
    if arp_info:
        asset.mac = arp_info.get('mac')
        asset.mac_vendor = arp_info.get('vendor')
        if arp_info.get('type_hint'):
            asset.asset_type = arp_info['type_hint']
        asset.discovery_methods.append('ARP')

    if dns_data.get(ip):
        asset.dns_hostname = dns_data[ip]
        asset.discovery_methods.append('DNS')

    icmp_info = icmp_data.get(ip, {})
    if icmp_info.get('alive'):
        asset.is_alive = True
        asset.ttl = icmp_info.get('ttl')
        if 'ICMP' not in asset.discovery_methods:
            asset.discovery_methods.append('ICMP')

    # If not alive from any Phase 1 method, still try per-host scans
    ports = options.get('ports', [])
    timeout = options.get('timeout', 2.0)
    snmp_communities = options.get('snmp_communities', ['public', 'private'])

    # --- Parallel per-host scans ---
    futures = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futures['tcp'] = ex.submit(
            _tcp_scan_host, ip, ports, timeout)

        if options.get('enable_netbios', True):
            futures['netbios'] = ex.submit(netbios_scan, ip, timeout)

        if options.get('enable_snmp', True):
            futures['snmp'] = ex.submit(
                snmp_scan, ip, snmp_communities, timeout)

        # Wait for TCP first to get open ports for Docker check
        tcp_result = futures['tcp'].result()
        open_port_nums = [p['port'] for p in tcp_result.get('ports', [])]

        if options.get('enable_docker', True):
            futures['docker'] = ex.submit(docker_scan, ip, open_port_nums)

        # Collect results
        if tcp_result.get('alive') or tcp_result.get('ports'):
            asset.is_alive = True
            asset.open_ports = tcp_result.get('ports', [])
            asset.discovery_methods.append('TCP-Scan')

        if 'netbios' in futures:
            nb = futures['netbios'].result()
            if nb and (nb.get('name') or nb.get('smb_os_version')):
                asset.netbios_name = nb.get('name')
                asset.os_build = nb.get('smb_build')
                # Store for OS fingerprint
                asset._smb_os_version = nb.get('smb_os_version')
                asset._smb_os_family = nb.get('smb_os_family')
                asset.discovery_methods.append('NetBIOS/SMB')

        if 'snmp' in futures:
            snmp = futures['snmp'].result()
            if snmp:
                asset.snmp_sysname = snmp.get('sysName')
                asset.snmp_sysdesc = snmp.get('sysDescr')
                asset.snmp_location = snmp.get('sysLocation')
                asset.snmp_interfaces = snmp.get('interfaces', [])
                asset.discovery_methods.append('SNMP')

        if 'docker' in futures:
            dk = futures['docker'].result()
            asset.is_docker_host = dk.get('is_docker_host', False)
            asset.docker_containers = dk.get('containers', [])
            if asset.is_docker_host:
                asset.discovery_methods.append('Docker-API')

        # Store for OS fingerprint
        asset._ssh_banner = tcp_result.get('ssh_banner', '')
        asset._http_server_header = tcp_result.get('http_server_header', '')

    return asset


# -----------------------------------------------------------------------
# OS + classification enrichment
# -----------------------------------------------------------------------

def _enrich_asset(asset: Asset) -> Asset:
    """Apply OS fingerprinting and asset classification."""
    os_data = {
        'smb_os_family':     getattr(asset, '_smb_os_family', None),
        'smb_os_version':    getattr(asset, '_smb_os_version', None),
        'ssh_banner':        getattr(asset, '_ssh_banner', ''),
        'http_server_header':getattr(asset, '_http_server_header', ''),
        'snmp_sysdesc':      asset.snmp_sysdesc,
        'ttl':               asset.ttl,
    }

    os_family, os_version, os_confidence, os_method = determine_os(os_data)
    asset.os_family = os_family
    asset.os_version = os_version or getattr(asset, '_smb_os_version', None)
    asset.os_confidence = os_confidence
    asset.os_method = os_method

    # Asset classification
    classification_data = {
        'mac_type_hint':  asset.asset_type if asset.asset_type != 'Unknown' else '',
        'os_family':      asset.os_family,
        'snmp_sysdesc':   asset.snmp_sysdesc or '',
        'open_ports':     asset.open_ports,
        'is_docker_host': asset.is_docker_host,
    }
    asset.asset_type = classify_asset(classification_data)

    # Hostname selection: AD > SMB/NetBIOS > SNMP > DNS
    asset.resolve_hostname()

    # Risk counts
    asset.compute_risk_counts()

    # Clean up temp attributes
    for attr in ('_smb_os_version', '_smb_os_family', '_ssh_banner', '_http_server_header'):
        if hasattr(asset, attr):
            delattr(asset, attr)

    return asset


# -----------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------

def run_discovery(target: str, options: dict,
                  scan_id: str = '',
                  on_progress=None,
                  on_asset=None) -> list:
    """
    Full enterprise asset discovery pipeline.

    Args:
        target:      CIDR subnet (e.g. "192.168.1.0/24") or single IP
        options:     Dict with keys:
                       ports, timeout, snmp_communities,
                       enable_netbios, enable_snmp, enable_docker, enable_dns_sweep
        scan_id:     Scan identifier string
        on_progress: Callback(done, total, phase) for progress updates
        on_asset:    Callback(asset_dict) called when each asset is ready

    Returns:
        List of Asset.to_dict() results
    """
    def progress(done, total, phase=''):
        if on_progress:
            on_progress(done, total, phase)

    # ----------------------------------------------------------------
    # Phase 1: Network-wide fast discovery
    # ----------------------------------------------------------------
    progress(0, 0, 'Phase 1: Network sweep (ARP + DNS + ICMP)')

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        arp_future  = ex.submit(arp_sweep, target)
        dns_future  = ex.submit(dns_sweep, target) if options.get('enable_dns_sweep', True) else None
        icmp_future = ex.submit(icmp_sweep, target)

    arp_data  = arp_future.result()
    dns_data  = dns_future.result() if dns_future else {}
    icmp_data = icmp_future.result()

    # Union of all discovered IPs
    all_ips = (
        set(arp_data.keys()) |
        set(dns_data.keys()) |
        {ip for ip, info in icmp_data.items() if info['alive']}
    )

    # Also include IPs in the range that might respond only to TCP
    # (add subnet hosts if target is CIDR — they'll be scanned in Phase 2)
    try:
        network = ipaddress.ip_network(target, strict=False)
        # Limit to reasonable scan size
        if network.num_addresses <= 4096:
            all_ips |= {str(h) for h in network.hosts()}
    except ValueError:
        all_ips.add(target)

    total = len(all_ips)
    progress(0, total, 'Phase 2: Per-host deep scan')

    # ----------------------------------------------------------------
    # Phase 2: Per-host parallel discovery
    # ----------------------------------------------------------------
    assets_dict = {}
    done_count = 0

    def scan_one(ip):
        return _discover_host(ip, options, scan_id, arp_data, dns_data, icmp_data)

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        future_map = {ex.submit(scan_one, ip): ip for ip in all_ips}
        for future in concurrent.futures.as_completed(future_map):
            ip = future_map[future]
            try:
                asset = future.result()
                done_count += 1
                progress(done_count, total, 'Phase 2: Per-host deep scan')

                # Only keep assets that are alive or have any discovery data
                if (asset.is_alive or asset.mac or asset.netbios_name or
                        asset.dns_hostname or asset.snmp_sysname):
                    assets_dict[ip] = asset
            except Exception:
                done_count += 1
                progress(done_count, total, 'Phase 2: Per-host deep scan')

    # ----------------------------------------------------------------
    # Phase 3: Enrichment
    # ----------------------------------------------------------------
    progress(0, len(assets_dict), 'Phase 3: OS fingerprinting & classification')

    results = []
    for i, (ip, asset) in enumerate(assets_dict.items()):
        enriched = _enrich_asset(asset)
        asset_dict = enriched.to_dict()
        results.append(asset_dict)
        if on_asset:
            on_asset(asset_dict)
        progress(i + 1, len(assets_dict), 'Phase 3: OS fingerprinting & classification')

    # Sort by IP
    results.sort(key=lambda a: tuple(int(x) for x in a['ip'].split('.')))

    return results
