"""
SNMP Discovery — query hosts via SNMP v1/v2c to retrieve:
  - sysName  (hostname)
  - sysDescr (OS string)
  - sysLocation
  - Interface table (ifDescr, ifPhysAddress, ifSpeed)

Requires: pysnmp (pip install pysnmp-lextudio)
Falls back gracefully if pysnmp is not installed.
"""
import socket

# Check if pysnmp is available
try:
    from pysnmp.hlapi import (
        getCmd, nextCmd,
        SnmpEngine, CommunityData,
        UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity,
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False


# -----------------------------------------------------------------------
# OIDs
# -----------------------------------------------------------------------
OID_SYSNAME    = '1.3.6.1.2.1.1.5.0'
OID_SYSDESCR   = '1.3.6.1.2.1.1.1.0'
OID_SYSUPTIME  = '1.3.6.1.2.1.1.3.0'
OID_SYSLOCATION= '1.3.6.1.2.1.1.6.0'
OID_SYSCONTACT = '1.3.6.1.2.1.1.4.0'

OID_IFDESCR    = '1.3.6.1.2.1.2.2.1.2'
OID_IFPHYSADDR = '1.3.6.1.2.1.2.2.1.6'
OID_IFSPEED    = '1.3.6.1.2.1.2.2.1.5'
OID_IFOPERSTATUS = '1.3.6.1.2.1.2.2.1.8'

DEFAULT_COMMUNITIES = ['public', 'private', 'community', 'cisco', 'admin']


def _is_port_open(ip: str, port: int = 161, timeout: float = 0.5) -> bool:
    """Quick UDP reachability check (send a byte, see if we get ICMP port-unreachable)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b'\x00', (ip, port))
            return True  # Assume open; pysnmp will verify
    except Exception:
        return False


def _snmp_get_pysnmp(ip: str, community: str, timeout: float = 1.5) -> dict:
    """Use pysnmp to GET system OIDs."""
    results = {}
    engine = SnmpEngine()
    auth = CommunityData(community, mpModel=1)  # mpModel=1 → SNMPv2c
    transport = UdpTransportTarget((ip, 161), timeout=timeout, retries=0)
    ctx = ContextData()

    oids = [
        ObjectType(ObjectIdentity(OID_SYSNAME)),
        ObjectType(ObjectIdentity(OID_SYSDESCR)),
        ObjectType(ObjectIdentity(OID_SYSLOCATION)),
        ObjectType(ObjectIdentity(OID_SYSCONTACT)),
    ]

    error_indication, error_status, error_index, var_binds = next(
        getCmd(engine, auth, transport, ctx, *oids)
    )

    if error_indication or error_status:
        return {}

    key_map = {
        OID_SYSNAME:     'sysName',
        OID_SYSDESCR:    'sysDescr',
        OID_SYSLOCATION: 'sysLocation',
        OID_SYSCONTACT:  'sysContact',
    }

    for var_bind in var_binds:
        oid_str = str(var_bind[0])
        value = str(var_bind[1])
        for k, label in key_map.items():
            if oid_str.startswith(k.split('.0')[0]):
                results[label] = value
                break

    return results


def _snmp_walk_interfaces_pysnmp(ip: str, community: str, timeout: float = 2.0) -> list:
    """Walk the interface table via SNMP."""
    interfaces = {}
    engine = SnmpEngine()
    auth = CommunityData(community, mpModel=1)
    transport = UdpTransportTarget((ip, 161), timeout=timeout, retries=0)
    ctx = ContextData()

    for walk_oid, field in [
        (OID_IFDESCR,     'descr'),
        (OID_IFPHYSADDR,  'mac'),
        (OID_IFSPEED,     'speed'),
        (OID_IFOPERSTATUS,'status'),
    ]:
        try:
            for error_indication, error_status, _, var_binds in nextCmd(
                engine, auth, transport, ctx,
                ObjectType(ObjectIdentity(walk_oid)),
                lexicographicMode=False,
                maxRows=50,
            ):
                if error_indication or error_status:
                    break
                for var_bind in var_binds:
                    oid_str = str(var_bind[0])
                    idx = oid_str.split('.')[-1]
                    if idx not in interfaces:
                        interfaces[idx] = {'index': idx}
                    value = var_bind[1]
                    # Format MAC bytes
                    if field == 'mac':
                        try:
                            raw = bytes(value)
                            if raw and len(raw) == 6:
                                mac = ':'.join(f'{b:02X}' for b in raw)
                                interfaces[idx][field] = mac
                            else:
                                interfaces[idx][field] = str(value)
                        except Exception:
                            interfaces[idx][field] = str(value)
                    elif field == 'speed':
                        try:
                            speed_bps = int(value)
                            if speed_bps >= 1_000_000_000:
                                interfaces[idx][field] = f'{speed_bps // 1_000_000_000}Gbps'
                            elif speed_bps >= 1_000_000:
                                interfaces[idx][field] = f'{speed_bps // 1_000_000}Mbps'
                            else:
                                interfaces[idx][field] = f'{speed_bps}bps'
                        except Exception:
                            interfaces[idx][field] = str(value)
                    else:
                        interfaces[idx][field] = str(value)
        except Exception:
            pass

    return [v for v in interfaces.values() if v.get('descr') and
            v.get('descr') not in ('lo', 'Loopback', 'lo0')]


# -----------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------

def snmp_scan(ip: str,
              communities: list = None,
              timeout: float = 1.5,
              walk_interfaces: bool = True) -> dict:
    """
    Query a host via SNMP.

    Args:
        ip:               Target IP address
        communities:      List of community strings to try
        timeout:          Per-attempt timeout
        walk_interfaces:  Whether to walk the interface table

    Returns:
        {
          'sysName': '...',
          'sysDescr': '...',
          'sysLocation': '...',
          'sysContact': '...',
          'community': 'public',   # the one that worked
          'interfaces': [...],
        }
        or {} if SNMP not available/responsive.
    """
    if not SNMP_AVAILABLE:
        return {}

    if communities is None:
        communities = DEFAULT_COMMUNITIES

    for community in communities:
        try:
            result = _snmp_get_pysnmp(ip, community, timeout=timeout)
            if result:
                result['community'] = community
                if walk_interfaces:
                    try:
                        result['interfaces'] = _snmp_walk_interfaces_pysnmp(
                            ip, community, timeout=timeout)
                    except Exception:
                        result['interfaces'] = []
                else:
                    result['interfaces'] = []
                return result
        except Exception:
            continue

    return {}
