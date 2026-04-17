"""State machine for Major Project security assessment workflow."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, override

from pydantic import BaseModel, Field

from agentex.lib.sdk.state_machine import StateMachine
from agentex.types.span import Span


class MajorProjectState(str, Enum):
    """States for Major Project security assessment workflow."""

    # Discovery Phase
    WAITING_FOR_TARGET = "waiting_for_target"
    DISCOVERING_ASSETS = "discovering_assets"
    GATHERING_THREAT_INTEL = "gathering_threat_intel"
    MAPPING_ATTACK_SURFACE = "mapping_attack_surface"

    # Analysis Phase
    REASONING_VULNERABILITIES = "reasoning_vulnerabilities"
    PRIORITIZING_TARGETS = "prioritizing_targets"

    # Exploitation Phase (Human Approval Required)
    AWAITING_EXPLOIT_APPROVAL = "awaiting_exploit_approval"
    GENERATING_EXPLOITS = "generating_exploits"
    MUTATING_PAYLOADS = "mutating_payloads"

    # Verification Phase
    VERIFYING_EXPLOITS = "verifying_exploits"
    VALIDATING_SAFETY = "validating_safety"

    # Reporting Phase
    GENERATING_REPORT = "generating_report"
    AWAITING_HUMAN_REVIEW = "awaiting_human_review"

    # Terminal States
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED_FOR_APPROVAL = "paused_for_approval"


class TargetScope(BaseModel):
    """Authorization and scope definition."""

    domains: List[str] = Field(default_factory=list)
    ip_ranges: List[str] = Field(default_factory=list)
    excluded_hosts: List[str] = Field(default_factory=list)
    authorized_until: Optional[datetime] = None
    rules_of_engagement: str = ""
    emergency_contact: str = ""
    authorization_document_id: Optional[str] = None
    testing_window_start: Optional[str] = None  # HH:MM format
    testing_window_end: Optional[str] = None  # HH:MM format


class DiscoveredAsset(BaseModel):
    """Asset discovered during reconnaissance."""

    id: str = ""
    hostname: str = ""
    ip_address: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    services: List[Dict[str, Any]] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    cloud_provider: Optional[str] = None
    web_server: Optional[str] = None
    operating_system: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    risk_score: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    vulnerability_count: int = 0

    def has_web_services(self) -> bool:
        """Check if asset has web services (HTTP/HTTPS ports)."""
        web_ports = {80, 443, 8080, 8443, 8000, 3000, 8008, 8888}
        return any(port in web_ports for port in self.ports)


class ThreatIntel(BaseModel):
    """Threat intelligence data."""

    cves: List[Dict[str, Any]] = Field(default_factory=list)
    exploits_available: List[Dict[str, Any]] = Field(default_factory=list)
    known_vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    osint_findings: List[Dict[str, Any]] = Field(default_factory=list)
    last_updated: Optional[datetime] = None


class Vulnerability(BaseModel):
    """Identified vulnerability."""

    id: str = ""
    name: str = ""
    severity: str = "info"  # critical, high, medium, low, info
    cvss_score: Optional[float] = None
    cve_ids: List[str] = Field(default_factory=list)
    affected_asset: str = ""
    affected_port: Optional[int] = None
    affected_service: Optional[str] = None
    description: str = ""
    evidence: str = ""
    exploitability: str = "unknown"  # easy, moderate, difficult, unknown
    verified: bool = False
    false_positive: bool = False
    scanner: str = ""
    discovered_at: Optional[datetime] = None


class ExploitAttempt(BaseModel):
    """Exploitation attempt record."""

    id: str = ""
    vulnerability_id: str = ""
    exploit_type: str = ""
    payload: str = ""
    timestamp: Optional[datetime] = None
    success: bool = False
    evidence: Optional[str] = None
    human_approved: bool = False
    approved_by: Optional[str] = None
    approval_timestamp: Optional[datetime] = None
    safety_validated: bool = False
    rollback_performed: bool = False


class Finding(BaseModel):
    """Security finding for reporting."""

    id: str = ""
    title: str = ""
    severity: str = "info"
    cvss_score: Optional[float] = None
    description: str = ""
    affected_assets: List[str] = Field(default_factory=list)
    evidence: str = ""
    remediation: str = ""
    references: List[str] = Field(default_factory=list)
    verified: bool = False
    exploit_attempted: bool = False
    exploit_successful: bool = False


class HumanDecision(BaseModel):
    """Record of human decisions."""

    decision_id: str = ""
    timestamp: Optional[datetime] = None
    decision_type: str = ""  # approve_exploit, reject_exploit, add_scope, etc.
    context: str = ""
    decision: str = ""
    decided_by: str = ""
    reasoning: Optional[str] = None


class MajorProjectData(BaseModel):
    """Data model for Major Project security assessment workflow."""

    # Input Configuration
    instruction: str = ""
    scan_type: str = "standard"  # passive, light, standard, aggressive, stealth

    # Target Configuration
    target_scope: Optional[TargetScope] = None
    scope_validated: bool = False

    # Discovery Phase Data
    discovered_assets: List[DiscoveredAsset] = Field(default_factory=list)
    threat_intel: Optional[ThreatIntel] = None
    attack_surface_mapped: bool = False

    # Analysis Phase Data
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    prioritized_targets: List[str] = Field(default_factory=list)
    attack_paths: List[Dict[str, Any]] = Field(default_factory=list)
    risk_matrix: Dict[str, Any] = Field(default_factory=dict)

    # Attack Chain Analysis - AI-discovered vulnerability combinations
    attack_chains: List[Dict[str, Any]] = Field(default_factory=list)

    # Exploitation Phase Data
    exploit_attempts: List[ExploitAttempt] = Field(default_factory=list)
    pending_approvals: List[Dict[str, Any]] = Field(default_factory=list)
    current_exploit_id: Optional[str] = None

    # Verification Phase Data
    verified_vulnerabilities: List[str] = Field(default_factory=list)
    false_positives: List[str] = Field(default_factory=list)

    # Reporting Data
    findings: List[Finding] = Field(default_factory=list)
    report_id: Optional[str] = None
    report_generated: bool = False
    executive_summary: str = ""

    # Result & Error Handling
    result: Dict[str, Any] = Field(default_factory=dict)
    error_message: str = ""
    errors: List[Dict[str, Any]] = Field(default_factory=list)

    # Workflow State
    task_id: Optional[str] = None
    trace_id: Optional[str] = None
    current_span: Optional[Span] = None
    waiting_for_user_input: bool = True
    waiting_for_approval: bool = False

    # Worker Agent Pattern - Communication with coordinator
    coordinator_task_id: Optional[str] = None
    worker_task_id: Optional[str] = None

    # Continuous Learning
    learnings: List[str] = Field(default_factory=list)
    false_positive_patterns: List[str] = Field(default_factory=list)
    successful_techniques: List[str] = Field(default_factory=list)

    # Human Escalation
    human_decisions: List[HumanDecision] = Field(default_factory=list)
    escalation_history: List[Dict[str, Any]] = Field(default_factory=list)

    # Agent Conversation History (for LLM reasoning)
    conversation_history: List[Dict[str, Any]] = Field(default_factory=list)

    # Statistics
    stats: Dict[str, Any] = Field(default_factory=lambda: {
        "assets_discovered": 0,
        "ports_scanned": 0,
        "vulnerabilities_found": 0,
        "exploits_attempted": 0,
        "exploits_successful": 0,
        "false_positives": 0,
        "scan_start_time": None,
        "scan_end_time": None,
        # AI Agent stats
        "ai_agent_findings": 0,
        "agent_iterations": 0,
        "endpoints_discovered": 0,
        # Attack Chain stats
        "attack_chains_found": 0,
        "critical_chains": 0,
        "high_chains": 0,
        # Zero-Day Discovery stats
        "zero_day_candidates": 0,
        "behavioral_anomalies": 0,
        "semantic_findings": 0,
        "novel_attacks": 0,
        # Verification stats
        "verified_findings": 0,
        "false_positive_rate": 0.0,
        # Learning stats
        "payloads_learned": 0,
        "patterns_identified": 0,
    })


class MajorProjectStateMachine(StateMachine[MajorProjectData]):
    """State machine for orchestrating Major Project security assessment workflow."""

    @override
    async def terminal_condition(self) -> bool:
        """
        For async agents, we never terminate - loop back to waiting for next target.
        The workflow continues accepting new assessment requests.
        """
        return False
