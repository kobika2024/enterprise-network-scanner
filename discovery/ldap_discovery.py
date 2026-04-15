"""
Active Directory / LDAP Discovery (optional module)

Queries Active Directory for all computer objects, returning:
  - Computer name, FQDN, OS, OS version, OU, last logon

Requires: ldap3 (pip install ldap3)
Falls back gracefully if not installed or credentials are wrong.
"""

try:
    from ldap3 import Server, Connection, SUBTREE, ALL, SIMPLE
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False

import re
from datetime import datetime, timedelta, timezone


def _filetime_to_iso(filetime: int) -> str:
    """Convert Windows FILETIME (100ns intervals since 1601-01-01) to ISO string."""
    try:
        if not filetime or filetime == 0:
            return ''
        # Convert to Unix timestamp
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        dt = epoch + timedelta(microseconds=filetime // 10)
        return dt.isoformat()
    except Exception:
        return str(filetime)


def _parse_ou(dn: str) -> str:
    """Extract OU path from Distinguished Name."""
    ous = re.findall(r'OU=([^,]+)', dn)
    return ' / '.join(reversed(ous)) if ous else ''


def _detect_dc_ip(domain: str) -> str:
    """Try to discover DC via DNS SRV record."""
    import socket
    try:
        # Try resolving _ldap._tcp.domain
        answers = socket.getaddrinfo(f'_ldap._tcp.{domain}', 389)
        if answers:
            return answers[0][4][0]
    except Exception:
        pass
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return domain


def query_ad(server_ip: str,
             domain: str,
             username: str,
             password: str,
             ssl: bool = False,
             timeout: int = 10) -> dict:
    """
    Query Active Directory for all computer objects.

    Args:
        server_ip: DC IP (or auto-discover from domain if empty)
        domain:    Domain name e.g. "corp.local"
        username:  Username (without domain prefix)
        password:  Password
        ssl:       Use LDAPS (port 636)
        timeout:   Connection timeout

    Returns:
        {
          'success': bool,
          'error': str,
          'computers': [
            {
              'name': 'WORKSTATION01',
              'fqdn': 'workstation01.corp.local',
              'os': 'Windows 10 Enterprise',
              'os_version': '10.0 (19045)',
              'ou': 'Workstations / IT',
              'dn': 'CN=WORKSTATION01,OU=...',
              'last_logon': '2026-04-10T08:30:00+00:00',
              'enabled': True,
            },
            ...
          ]
        }
    """
    if not LDAP3_AVAILABLE:
        return {
            'success': False,
            'error': 'ldap3 package not installed. Run: pip install ldap3',
            'computers': [],
        }

    # Auto-discover DC if not provided
    if not server_ip:
        server_ip = _detect_dc_ip(domain)

    port = 636 if ssl else 389

    try:
        srv = Server(server_ip, port=port, use_ssl=ssl,
                     connect_timeout=timeout, get_info=ALL)

        bind_user = f'{domain}\\{username}'
        conn = Connection(
            srv,
            user=bind_user,
            password=password,
            authentication=SIMPLE,
            auto_bind=True,
            receive_timeout=timeout,
        )

        # Build base DN from domain
        base_dn = ','.join(f'DC={part}' for part in domain.split('.'))

        # Search for all computer objects
        conn.search(
            search_base=base_dn,
            search_filter='(objectClass=computer)',
            search_scope=SUBTREE,
            attributes=[
                'cn', 'dNSHostName', 'operatingSystem',
                'operatingSystemVersion', 'distinguishedName',
                'lastLogonTimestamp', 'userAccountControl',
                'whenCreated', 'description',
            ],
            paged_size=500,
        )

        computers = []
        for entry in conn.entries:
            def safe(attr):
                try:
                    val = getattr(entry, attr).value
                    return str(val) if val is not None else None
                except Exception:
                    return None

            # Check if account is disabled (UAC bit 2 = 0x2 = disabled)
            try:
                uac = int(entry.userAccountControl.value or 0)
                enabled = not bool(uac & 0x2)
            except Exception:
                enabled = True

            # Last logon timestamp
            try:
                ll_raw = entry.lastLogonTimestamp.value
                if ll_raw and isinstance(ll_raw, int):
                    last_logon = _filetime_to_iso(ll_raw)
                elif ll_raw:
                    last_logon = str(ll_raw)
                else:
                    last_logon = ''
            except Exception:
                last_logon = ''

            dn = safe('distinguishedName') or ''

            computers.append({
                'name':          safe('cn') or '',
                'fqdn':          safe('dNSHostName'),
                'os':            safe('operatingSystem'),
                'os_version':    safe('operatingSystemVersion'),
                'ou':            _parse_ou(dn),
                'dn':            dn,
                'last_logon':    last_logon,
                'enabled':       enabled,
                'description':   safe('description'),
            })

        conn.unbind()

        return {
            'success': True,
            'error': None,
            'domain': domain,
            'base_dn': base_dn,
            'computers': computers,
            'total': len(computers),
        }

    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'computers': [],
        }
