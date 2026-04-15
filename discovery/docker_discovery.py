"""
Docker Container Discovery

Attempts to connect to Docker API on:
  - HTTP  port 2375 (unauthenticated)
  - HTTPS port 2376 (TLS, skip cert verification for internal scans)

Also checks Kubernetes API on port 6443 / 8080.
"""
import requests
import urllib3

# Suppress InsecureRequestWarning for internal scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DOCKER_TIMEOUT = 3.0

# Try docker SDK if available
try:
    import docker as docker_sdk
    DOCKER_SDK_AVAILABLE = True
except ImportError:
    DOCKER_SDK_AVAILABLE = False


def _format_container(c: dict) -> dict:
    """Normalize a container record from Docker API JSON."""
    names = c.get('Names', c.get('name', []))
    if isinstance(names, list):
        name = names[0].lstrip('/') if names else ''
    else:
        name = str(names).lstrip('/')

    image = c.get('Image', c.get('image', ''))
    status = c.get('Status', c.get('status', ''))
    state = c.get('State', c.get('state', ''))

    # Ports: can be dict or list depending on API version
    raw_ports = c.get('Ports', c.get('ports', []))
    ports = []
    if isinstance(raw_ports, list):
        for p in raw_ports:
            if isinstance(p, dict):
                public = p.get('PublicPort', '')
                private = p.get('PrivatePort', '')
                proto = p.get('Type', 'tcp')
                if public:
                    ports.append(f'{public}:{private}/{proto}')
                else:
                    ports.append(f'{private}/{proto}')
    elif isinstance(raw_ports, dict):
        for binding, host_bindings in raw_ports.items():
            if host_bindings:
                for hb in host_bindings:
                    ports.append(f'{hb.get("HostPort", "")}:{binding}')
            else:
                ports.append(binding)

    return {
        'id': (c.get('Id') or c.get('id') or '')[:12],
        'name': name,
        'image': image,
        'status': status or state,
        'ports': ports,
    }


def _docker_http(ip: str, port: int, scheme: str = 'http') -> list:
    """
    Query Docker API via raw HTTP/HTTPS.
    Returns list of formatted container dicts, or [] on failure.
    """
    base = f'{scheme}://{ip}:{port}'
    try:
        r = requests.get(
            f'{base}/containers/json',
            params={'all': 'true'},
            timeout=DOCKER_TIMEOUT,
            verify=False,
        )
        if r.status_code == 200:
            return [_format_container(c) for c in r.json()]
    except Exception:
        pass
    return []


def _docker_sdk_connect(ip: str, port: int) -> list:
    """Try docker SDK (handles some edge cases SDK has shortcuts for)."""
    if not DOCKER_SDK_AVAILABLE:
        return []
    try:
        client = docker_sdk.DockerClient(
            base_url=f'tcp://{ip}:{port}',
            timeout=int(DOCKER_TIMEOUT),
        )
        containers = client.containers.list(all=True)
        result = []
        for c in containers:
            tags = c.image.tags
            result.append({
                'id': c.short_id,
                'name': c.name,
                'image': tags[0] if tags else c.image.short_id,
                'status': c.status,
                'ports': [f'{h}:{p}' for p, bindings in (c.ports or {}).items()
                          for h in (bindings or [{'HostPort': ''}])
                          for h_port in [h.get('HostPort', '')]],
            })
        client.close()
        return result
    except Exception:
        return []


def _check_kubernetes(ip: str) -> dict:
    """Check if Kubernetes API server is running."""
    for port, scheme in [(6443, 'https'), (8080, 'http')]:
        try:
            r = requests.get(
                f'{scheme}://{ip}:{port}/version',
                timeout=DOCKER_TIMEOUT,
                verify=False,
            )
            if r.status_code in (200, 401, 403):
                data = {}
                try:
                    data = r.json()
                except Exception:
                    pass
                return {
                    'kubernetes': True,
                    'k8s_port': port,
                    'k8s_version': data.get('gitVersion', ''),
                }
        except Exception:
            pass
    return {}


# -----------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------

def docker_scan(ip: str, open_port_numbers: list = None) -> dict:
    """
    Detect Docker containers and Kubernetes on a host.

    Args:
        ip:               Target IP
        open_port_numbers: List of known open ports (to skip unnecessary attempts)

    Returns:
        {
          'is_docker_host': bool,
          'containers': [...],
          'kubernetes': bool,
          'k8s_version': '...',
        }
    """
    result = {
        'is_docker_host': False,
        'containers': [],
        'kubernetes': False,
        'k8s_version': '',
    }

    known_ports = set(open_port_numbers or [])
    containers = []

    # HTTP port 2375
    if not known_ports or 2375 in known_ports:
        # Try SDK first (more robust), then raw HTTP
        c = _docker_sdk_connect(ip, 2375)
        if not c:
            c = _docker_http(ip, 2375, 'http')
        if c is not None and len(c) >= 0:
            # Even empty list means Docker API responded
            try:
                # Verify it's actually Docker by checking version endpoint
                r = requests.get(f'http://{ip}:2375/version',
                                 timeout=DOCKER_TIMEOUT)
                if r.status_code == 200:
                    containers.extend(c)
                    result['is_docker_host'] = True
            except Exception:
                if c:  # non-empty response = Docker
                    containers.extend(c)
                    result['is_docker_host'] = True

    # HTTPS port 2376
    if not result['is_docker_host'] and (not known_ports or 2376 in known_ports):
        c = _docker_http(ip, 2376, 'https')
        if c:
            containers.extend(c)
            result['is_docker_host'] = True

    result['containers'] = containers

    # Kubernetes check
    k8s_ports = {6443, 8080}
    if not known_ports or k8s_ports & known_ports:
        k8s = _check_kubernetes(ip)
        result.update(k8s)

    return result
