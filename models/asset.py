"""
Unified Asset data model for enterprise network discovery.
All discovery modules produce and merge into this structure.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class AssetPort:
    port: int
    service: str
    banner: str
    risk: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO

    def to_dict(self) -> dict:
        return {
            'port': self.port,
            'service': self.service,
            'banner': self.banner,
            'risk': self.risk,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'AssetPort':
        return cls(
            port=d.get('port', 0),
            service=d.get('service', ''),
            banner=d.get('banner', ''),
            risk=d.get('risk', 'INFO'),
        )


@dataclass
class Asset:
    # --- Identity ---
    ip: str
    mac: Optional[str] = None
    mac_vendor: Optional[str] = None

    # --- Names (priority: AD > SMB > NetBIOS > SNMP > DNS) ---
    hostname: Optional[str] = None
    netbios_name: Optional[str] = None
    dns_hostname: Optional[str] = None
    fqdn: Optional[str] = None

    # --- OS Detection (priority: SMB > SSH-banner > SNMP > TTL) ---
    os_family: Optional[str] = None       # "Windows" / "Linux" / "Network Device"
    os_version: Optional[str] = None      # "Windows Server 2022" / "Ubuntu 22.04"
    os_build: Optional[str] = None        # Windows build number from SMB negotiate
    os_confidence: Optional[str] = None   # HIGH / MEDIUM / LOW
    os_method: Optional[str] = None       # "SMB-Negotiate" / "SSH-Banner" / "TTL"

    # --- Classification ---
    asset_type: str = 'Unknown'
    # Server / Workstation / VM / Container / Network Device / Printer / Unknown

    # --- Network ---
    open_ports: list = field(default_factory=list)  # list[AssetPort]
    ttl: Optional[int] = None
    is_alive: bool = False

    # --- SNMP ---
    snmp_sysname: Optional[str] = None
    snmp_sysdesc: Optional[str] = None
    snmp_location: Optional[str] = None
    snmp_interfaces: list = field(default_factory=list)

    # --- Docker ---
    is_docker_host: bool = False
    docker_containers: list = field(default_factory=list)

    # --- Active Directory ---
    ad_computer_name: Optional[str] = None
    ad_os: Optional[str] = None
    ad_os_version: Optional[str] = None
    ad_ou: Optional[str] = None
    ad_last_logon: Optional[str] = None

    # --- Discovery metadata ---
    discovery_methods: list = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    scan_id: str = ''

    # --- Computed risk ---
    critical_ports: int = 0
    high_ports: int = 0

    # ------------------------------------------------------------------
    # Merge: fill None fields from another Asset (non-destructive)
    # ------------------------------------------------------------------
    def merge(self, other: 'Asset') -> None:
        """Merge data from another Asset object. Only fills fields that are None."""
        for attr in ('mac', 'mac_vendor', 'netbios_name', 'dns_hostname', 'fqdn',
                     'os_family', 'os_version', 'os_build', 'os_confidence', 'os_method',
                     'snmp_sysname', 'snmp_sysdesc', 'snmp_location',
                     'ad_computer_name', 'ad_os', 'ad_os_version', 'ad_ou', 'ad_last_logon',
                     'ttl'):
            if getattr(self, attr) is None and getattr(other, attr) is not None:
                setattr(self, attr, getattr(other, attr))

        if not self.is_alive and other.is_alive:
            self.is_alive = other.is_alive

        if not self.is_docker_host and other.is_docker_host:
            self.is_docker_host = other.is_docker_host
            self.docker_containers = other.docker_containers

        if not self.snmp_interfaces and other.snmp_interfaces:
            self.snmp_interfaces = other.snmp_interfaces

        if not self.open_ports and other.open_ports:
            self.open_ports = other.open_ports

        # Merge discovery methods (unique)
        for m in other.discovery_methods:
            if m not in self.discovery_methods:
                self.discovery_methods.append(m)

        self.last_seen = datetime.utcnow().isoformat()

    # ------------------------------------------------------------------
    # Hostname selection
    # ------------------------------------------------------------------
    def resolve_hostname(self) -> None:
        """Pick the best available hostname with AD > SMB/NetBIOS > SNMP > DNS priority."""
        self.hostname = (
            self.ad_computer_name
            or self.netbios_name
            or self.snmp_sysname
            or self.dns_hostname
            or self.fqdn
        )

    # ------------------------------------------------------------------
    # Port risk counters
    # ------------------------------------------------------------------
    def compute_risk_counts(self) -> None:
        self.critical_ports = sum(1 for p in self.open_ports if p.get('risk') == 'CRITICAL')
        self.high_ports = sum(1 for p in self.open_ports if p.get('risk') == 'HIGH')

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            'ip': self.ip,
            'mac': self.mac,
            'mac_vendor': self.mac_vendor,
            'hostname': self.hostname,
            'netbios_name': self.netbios_name,
            'dns_hostname': self.dns_hostname,
            'fqdn': self.fqdn,
            'os_family': self.os_family,
            'os_version': self.os_version,
            'os_build': self.os_build,
            'os_confidence': self.os_confidence,
            'os_method': self.os_method,
            'asset_type': self.asset_type,
            'open_ports': self.open_ports,
            'ttl': self.ttl,
            'is_alive': self.is_alive,
            'snmp_sysname': self.snmp_sysname,
            'snmp_sysdesc': self.snmp_sysdesc,
            'snmp_location': self.snmp_location,
            'snmp_interfaces': self.snmp_interfaces,
            'is_docker_host': self.is_docker_host,
            'docker_containers': self.docker_containers,
            'ad_computer_name': self.ad_computer_name,
            'ad_os': self.ad_os,
            'ad_os_version': self.ad_os_version,
            'ad_ou': self.ad_ou,
            'ad_last_logon': self.ad_last_logon,
            'discovery_methods': self.discovery_methods,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'scan_id': self.scan_id,
            'critical_ports': self.critical_ports,
            'high_ports': self.high_ports,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'Asset':
        a = cls(ip=d['ip'])
        for k, v in d.items():
            if hasattr(a, k):
                setattr(a, k, v)
        return a
