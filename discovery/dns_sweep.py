"""
DNS Reverse Sweep — bulk PTR record lookups across an IP range.
Uses only Python stdlib (socket.gethostbyaddr).
"""
import socket
import ipaddress
import concurrent.futures


def _reverse_lookup(ip: str, timeout: float = 0.5) -> tuple:
    """Return (ip, hostname) or (ip, None) on failure."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        return ip, name
    except Exception:
        return ip, None
    finally:
        socket.setdefaulttimeout(old_timeout)


def dns_sweep(target: str, timeout: float = 0.5, max_workers: int = 50) -> dict:
    """
    Perform bulk reverse DNS lookups for all IPs in target subnet.

    Args:
        target: CIDR notation (e.g. "192.168.1.0/24") or single IP
        timeout: per-lookup timeout in seconds
        max_workers: concurrent lookup threads

    Returns:
        {ip_str: hostname_str}  — only IPs that resolved
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(h) for h in network.hosts()]
    except ValueError:
        hosts = [target]

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_reverse_lookup, ip, timeout): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            try:
                ip, name = future.result()
                if name:
                    results[ip] = name
            except Exception:
                pass

    return results
