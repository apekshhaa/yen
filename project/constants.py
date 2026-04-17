"""Constants for Major-Project AI Pentester Agent."""
import os
from enum import Enum


# LLM Configuration - matches other agents pattern (aws-hero, dr-nova-science)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://openrouter.ai/api/v1")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "deepseek/deepseek-v3.2-exp")


class SafetyLevel(str, Enum):
    """Safety levels for operations."""

    INFO_GATHERING = "info_gathering"  # Passive reconnaissance
    VULNERABILITY_SCAN = "vulnerability_scan"  # Non-exploitative scanning
    LOW_IMPACT = "low_impact"  # XSS, info disclosure
    MEDIUM_IMPACT = "medium_impact"  # SQLi, auth bypass
    HIGH_IMPACT = "high_impact"  # RCE, privilege escalation
    CRITICAL = "critical"  # Zero-day, destructive


class ApprovalLevel(str, Enum):
    """Human approval levels."""

    AUTO_APPROVE = "auto_approve"
    HUMAN_APPROVAL = "human_approval"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"
    SENIOR_APPROVAL_REQUIRED = "senior_approval_required"


# Safety level to approval mapping
SAFETY_APPROVAL_MATRIX = {
    SafetyLevel.INFO_GATHERING: ApprovalLevel.AUTO_APPROVE,
    SafetyLevel.VULNERABILITY_SCAN: ApprovalLevel.AUTO_APPROVE,
    SafetyLevel.LOW_IMPACT: ApprovalLevel.AUTO_APPROVE,
    SafetyLevel.MEDIUM_IMPACT: ApprovalLevel.HUMAN_APPROVAL,
    SafetyLevel.HIGH_IMPACT: ApprovalLevel.HUMAN_APPROVAL_REQUIRED,
    SafetyLevel.CRITICAL: ApprovalLevel.SENIOR_APPROVAL_REQUIRED,
}


class VulnerabilitySeverity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# CVSS score to severity mapping
CVSS_SEVERITY_MAP = {
    (9.0, 10.0): VulnerabilitySeverity.CRITICAL,
    (7.0, 8.9): VulnerabilitySeverity.HIGH,
    (4.0, 6.9): VulnerabilitySeverity.MEDIUM,
    (0.1, 3.9): VulnerabilitySeverity.LOW,
    (0.0, 0.0): VulnerabilitySeverity.INFO,
}


class ExploitStatus(str, Enum):
    """Exploit attempt status."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    SUCCESSFUL = "successful"
    FAILED = "failed"
    VERIFIED = "verified"


class ScanType(str, Enum):
    """Types of scans."""

    PASSIVE = "passive"  # No active probing
    LIGHT = "light"  # Limited active scanning
    STANDARD = "standard"  # Standard pentest
    AGGRESSIVE = "aggressive"  # Full aggressive scan
    STEALTH = "stealth"  # Low and slow


# Default timeouts (seconds)
TIMEOUTS = {
    "nmap_scan": 300,
    "nuclei_scan": 600,
    "subfinder": 120,
    "httpx": 60,
    "exploit_execution": 180,
    "human_approval": 14400,  # 4 hours
    "activity_default": 120,
}


# Rate limits
RATE_LIMITS = {
    "requests_per_second": 10,
    "concurrent_scans": 5,
    "max_targets_per_scan": 100,
}


# Max iterations for agentic loops
MAX_AGENT_ITERATIONS = 15


# Tool call display settings
TOOL_DISPLAY = {
    "show_command": True,
    "show_target": True,
    "show_result_summary": True,
    "truncate_result_at": 5000,
}
