"""Report models for Major-Project agent."""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from project.models.finding import Finding, FindingSummary


class ReportFormat(str, Enum):
    """Output format for reports."""

    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    JSON = "json"


class ReportType(str, Enum):
    """Type of security report."""

    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    FULL = "full"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"


class ExecutiveSummary(BaseModel):
    """Executive summary for reports."""

    overall_risk_rating: str = "medium"  # critical, high, medium, low
    risk_score: float = 0.0

    # Key metrics
    total_assets_tested: int = 0
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0

    # Assessment overview
    assessment_scope: str = ""
    assessment_duration: str = ""
    methodology: str = ""

    # Key findings
    key_findings: List[str] = Field(default_factory=list)
    critical_risks: List[str] = Field(default_factory=list)

    # Recommendations
    immediate_actions: List[str] = Field(default_factory=list)
    short_term_actions: List[str] = Field(default_factory=list)
    long_term_actions: List[str] = Field(default_factory=list)

    # Positive observations
    positive_observations: List[str] = Field(default_factory=list)

    # Comparison (if available)
    previous_assessment_comparison: Optional[Dict[str, Any]] = None


class ReportSection(BaseModel):
    """Section of a security report."""

    id: str = ""
    title: str = ""
    order: int = 0
    content: str = ""
    subsections: List["ReportSection"] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    charts: List[Dict[str, Any]] = Field(default_factory=list)
    tables: List[Dict[str, Any]] = Field(default_factory=list)


class Report(BaseModel):
    """Complete penetration test report."""

    id: str = ""
    title: str = "Security Assessment Report"
    report_type: ReportType = ReportType.FULL
    version: str = "1.0"

    # Metadata
    generated_at: Optional[datetime] = None
    assessment_start: Optional[datetime] = None
    assessment_end: Optional[datetime] = None
    assessor: str = "Major-Project AI Pentester"
    organization: str = ""
    classification: str = "Confidential"

    # Scope
    scope_description: str = ""
    in_scope_targets: List[str] = Field(default_factory=list)
    out_of_scope_targets: List[str] = Field(default_factory=list)
    rules_of_engagement: str = ""
    limitations: List[str] = Field(default_factory=list)

    # Methodology
    methodology_description: str = ""
    tools_used: List[str] = Field(default_factory=list)
    testing_phases: List[str] = Field(default_factory=list)

    # Executive Summary
    executive_summary: Optional[ExecutiveSummary] = None

    # Findings Summary
    findings_summary: Optional[FindingSummary] = None

    # Detailed Findings
    findings: List[Finding] = Field(default_factory=list)

    # Report Sections
    sections: List[ReportSection] = Field(default_factory=list)

    # Appendices
    appendices: List[Dict[str, Any]] = Field(default_factory=list)

    # Statistics
    stats: Dict[str, Any] = Field(default_factory=lambda: {
        "total_hosts_scanned": 0,
        "total_ports_scanned": 0,
        "total_services_identified": 0,
        "total_vulnerabilities": 0,
        "exploits_attempted": 0,
        "exploits_successful": 0,
        "scan_duration_hours": 0.0,
    })

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_asset(self, asset: str) -> List[Finding]:
        """Get findings filtered by affected asset."""
        return [f for f in self.findings if asset in f.affected_assets]

    def to_markdown(self) -> str:
        """Generate markdown version of report."""
        lines = [
            f"# {self.title}",
            "",
            f"**Report Version:** {self.version}",
            f"**Generated:** {self.generated_at}",
            f"**Classification:** {self.classification}",
            "",
            "---",
            "",
        ]

        if self.executive_summary:
            lines.extend([
                "## Executive Summary",
                "",
                f"**Overall Risk Rating:** {self.executive_summary.overall_risk_rating.upper()}",
                f"**Risk Score:** {self.executive_summary.risk_score:.1f}/100",
                "",
                "### Key Findings",
                "",
            ])
            for finding in self.executive_summary.key_findings:
                lines.append(f"- {finding}")
            lines.append("")

        if self.findings_summary:
            lines.extend([
                "## Vulnerability Summary",
                "",
                f"| Severity | Count |",
                f"|----------|-------|",
                f"| Critical | {self.findings_summary.critical_count} |",
                f"| High | {self.findings_summary.high_count} |",
                f"| Medium | {self.findings_summary.medium_count} |",
                f"| Low | {self.findings_summary.low_count} |",
                f"| Info | {self.findings_summary.info_count} |",
                "",
            ])

        lines.extend([
            "## Detailed Findings",
            "",
        ])

        for i, finding in enumerate(self.findings, 1):
            lines.extend([
                f"### {i}. {finding.title}",
                "",
                f"**Severity:** {finding.severity.upper()}",
                f"**CVSS Score:** {finding.cvss_score or 'N/A'}",
                "",
                "**Description:**",
                finding.description,
                "",
                "**Affected Assets:**",
            ])
            for asset in finding.affected_assets:
                lines.append(f"- {asset}")
            lines.extend([
                "",
                "**Remediation:**",
                finding.remediation_summary,
                "",
                "---",
                "",
            ])

        return "\n".join(lines)
