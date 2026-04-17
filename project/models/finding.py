"""Finding models for Major-Project agent."""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class FindingStatus(str, Enum):
    """Status of a finding."""

    DRAFT = "draft"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED = "accepted"
    REMEDIATED = "remediated"


class Finding(BaseModel):
    """Security finding for reporting."""

    id: str = ""
    title: str = ""
    severity: str = "info"  # critical, high, medium, low, info
    status: FindingStatus = FindingStatus.DRAFT

    # CVSS
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    # Classification
    category: str = ""
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

    # Description
    summary: str = ""
    description: str = ""
    technical_details: str = ""

    # Affected Assets
    affected_assets: List[str] = Field(default_factory=list)
    affected_urls: List[str] = Field(default_factory=list)
    affected_parameters: List[str] = Field(default_factory=list)

    # Evidence
    evidence: str = ""
    proof_of_concept: str = ""
    screenshots: List[str] = Field(default_factory=list)
    request_response: List[Dict[str, str]] = Field(default_factory=list)

    # Exploitation
    exploited: bool = False
    exploit_successful: bool = False
    exploit_evidence: str = ""

    # Impact
    business_impact: str = ""
    technical_impact: str = ""
    data_at_risk: List[str] = Field(default_factory=list)
    compliance_impact: List[str] = Field(default_factory=list)  # GDPR, PCI-DSS, etc.

    # Remediation
    remediation_summary: str = ""
    remediation_steps: List[str] = Field(default_factory=list)
    remediation_effort: str = "medium"  # low, medium, high
    remediation_priority: int = 0  # 1-5, 1 being highest priority
    patch_available: bool = False
    patch_url: Optional[str] = None
    workaround: Optional[str] = None

    # References
    references: List[str] = Field(default_factory=list)
    cve_references: List[str] = Field(default_factory=list)

    # Metadata
    discovered_by: str = ""  # scanner name or manual
    discovered_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None
    verified_by: Optional[str] = None

    # Related vulnerabilities
    vulnerability_ids: List[str] = Field(default_factory=list)
    exploit_ids: List[str] = Field(default_factory=list)


class FindingSummary(BaseModel):
    """Summary of findings for executive reporting."""

    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Verification stats
    verified_count: int = 0
    false_positive_count: int = 0
    exploited_count: int = 0

    # Categories
    by_category: Dict[str, int] = Field(default_factory=dict)
    by_asset: Dict[str, int] = Field(default_factory=dict)

    # Risk metrics
    overall_risk_score: float = 0.0
    average_cvss: float = 0.0
    highest_cvss: float = 0.0

    # Top findings
    top_critical_findings: List[str] = Field(default_factory=list)
    quick_wins: List[str] = Field(default_factory=list)  # Easy to fix, high impact

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score."""
        weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1,
            "info": 0,
        }
        total_weight = (
            self.critical_count * weights["critical"]
            + self.high_count * weights["high"]
            + self.medium_count * weights["medium"]
            + self.low_count * weights["low"]
        )
        if self.total_findings == 0:
            return 0.0
        return min(total_weight / self.total_findings * 10, 100.0)
