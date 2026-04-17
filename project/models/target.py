"""Target models for Major-Project agent."""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TargetType(str, Enum):
    """Type of target."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    IP_RANGE = "ip_range"
    URL = "url"
    CLOUD_ASSET = "cloud_asset"


class ServiceInfo(BaseModel):
    """Information about a discovered service."""

    port: int
    protocol: str = "tcp"
    service_name: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    banner: str = ""
    state: str = "open"
    vulnerabilities: List[str] = Field(default_factory=list)


class Target(BaseModel):
    """Target for penetration testing."""

    id: str = ""
    target_type: TargetType = TargetType.DOMAIN
    value: str = ""  # domain name, IP, URL, etc.

    # Resolved information
    resolved_ips: List[str] = Field(default_factory=list)
    resolved_hostnames: List[str] = Field(default_factory=list)

    # Discovery data
    subdomains: List[str] = Field(default_factory=list)
    services: List[ServiceInfo] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    web_server: Optional[str] = None
    operating_system: Optional[str] = None

    # Cloud information
    cloud_provider: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_service: Optional[str] = None

    # SSL/TLS information
    ssl_enabled: bool = False
    ssl_certificate: Optional[Dict[str, Any]] = None
    ssl_issues: List[str] = Field(default_factory=list)

    # Metadata
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    last_scanned: Optional[datetime] = None

    # Risk assessment
    risk_score: float = 0.0
    vulnerability_count: int = 0
    critical_count: int = 0
    high_count: int = 0

    # Status
    in_scope: bool = True
    scan_status: str = "pending"  # pending, scanning, completed, failed

    def get_scan_targets(self) -> List[str]:
        """Get list of targets to scan (IPs or hostnames)."""
        if self.resolved_ips:
            return self.resolved_ips
        return [self.value]

    def get_open_ports(self) -> List[int]:
        """Get list of open ports."""
        return [s.port for s in self.services if s.state == "open"]

    def has_web_services(self) -> bool:
        """Check if target has web services."""
        web_ports = {80, 443, 8080, 8443, 8000, 3000}
        return any(s.port in web_ports for s in self.services)
