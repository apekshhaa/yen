"""Attack Chain models for Major-Project agent.

Attack chains represent sequences of vulnerabilities that can be combined
to achieve a higher-impact exploit than any single vulnerability alone.
"""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ChainComplexity(str, Enum):
    """How complex is the attack chain to execute."""

    TRIVIAL = "trivial"      # Can be automated easily
    LOW = "low"              # Requires basic skills
    MEDIUM = "medium"        # Requires moderate expertise
    HIGH = "high"            # Requires advanced skills
    EXPERT = "expert"        # Requires expert-level knowledge


class ChainImpact(str, Enum):
    """The impact level of a successful chain exploitation."""

    CRITICAL = "critical"    # Full system compromise, data breach
    HIGH = "high"            # Significant data access, privilege escalation
    MEDIUM = "medium"        # Limited data access, partial control
    LOW = "low"              # Information disclosure, minor impact


class ChainType(str, Enum):
    """Common attack chain patterns."""

    PRIVILEGE_ESCALATION = "privilege_escalation"
    ACCOUNT_TAKEOVER = "account_takeover"
    DATA_EXFILTRATION = "data_exfiltration"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    DENIAL_OF_SERVICE = "denial_of_service"
    SUPPLY_CHAIN = "supply_chain"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    NETWORK_PIVOT = "network_pivot"
    CUSTOM = "custom"


class ChainStep(BaseModel):
    """A single step in an attack chain."""

    step_number: int = 0
    vulnerability_id: str = ""
    vulnerability_name: str = ""
    vulnerability_type: str = ""

    # What this step achieves
    action: str = ""  # e.g., "Exploit IDOR to get user email"
    objective: str = ""  # e.g., "Obtain victim's email address"

    # Technical details
    target_url: Optional[str] = None
    target_parameter: Optional[str] = None
    payload: Optional[str] = None
    expected_response: Optional[str] = None

    # Prerequisites
    prerequisites: List[str] = Field(default_factory=list)  # What must be true before this step

    # Output that feeds into next step
    output_data: str = ""  # e.g., "victim_email"
    output_description: str = ""  # e.g., "Email address of target user"


class AttackChain(BaseModel):
    """
    An attack chain combining multiple vulnerabilities for greater impact.

    Attack chains are the key to discovering zero-day-like impacts by
    combining individually low/medium severity findings into critical
    exploit paths.
    """

    id: str = ""
    name: str = ""
    description: str = ""

    # Classification
    chain_type: ChainType = ChainType.CUSTOM
    complexity: ChainComplexity = ChainComplexity.MEDIUM
    impact: ChainImpact = ChainImpact.MEDIUM

    # Combined severity (often higher than individual vulns)
    combined_severity: str = "high"  # critical, high, medium, low
    combined_cvss: Optional[float] = None

    # The chain steps
    steps: List[ChainStep] = Field(default_factory=list)
    total_steps: int = 0

    # Individual vulnerabilities in the chain
    vulnerability_ids: List[str] = Field(default_factory=list)
    vulnerability_names: List[str] = Field(default_factory=list)

    # What the chain achieves
    final_objective: str = ""  # e.g., "Complete account takeover"
    business_impact: str = ""  # e.g., "Attacker gains full control of any user account"

    # Affected targets
    affected_assets: List[str] = Field(default_factory=list)
    entry_point: str = ""  # Where the attack starts

    # Proof of Concept
    poc_available: bool = False
    poc_script: Optional[str] = None
    poc_steps: List[str] = Field(default_factory=list)

    # Risk assessment
    likelihood: str = "medium"  # low, medium, high
    exploitability: str = "medium"  # trivial, easy, medium, hard
    requires_authentication: bool = False
    requires_user_interaction: bool = False

    # AI reasoning
    ai_reasoning: str = ""  # The LLM's reasoning about why this chain works
    confidence_score: float = 0.0  # 0.0 to 1.0

    # Remediation
    remediation_summary: str = ""
    breaking_point: str = ""  # Which step to fix to break the entire chain
    remediation_steps: List[str] = Field(default_factory=list)

    # Metadata
    discovered_at: Optional[datetime] = None
    discovered_by: str = "ai_chain_reasoner"
    verified: bool = False
    verified_at: Optional[datetime] = None

    def get_risk_score(self) -> float:
        """Calculate risk score based on impact and complexity."""
        impact_scores = {
            ChainImpact.CRITICAL: 10.0,
            ChainImpact.HIGH: 7.5,
            ChainImpact.MEDIUM: 5.0,
            ChainImpact.LOW: 2.5,
        }

        complexity_multipliers = {
            ChainComplexity.TRIVIAL: 1.5,
            ChainComplexity.LOW: 1.3,
            ChainComplexity.MEDIUM: 1.0,
            ChainComplexity.HIGH: 0.7,
            ChainComplexity.EXPERT: 0.5,
        }

        base_score = impact_scores.get(self.impact, 5.0)
        multiplier = complexity_multipliers.get(self.complexity, 1.0)

        # Bonus for verified chains
        if self.verified:
            multiplier *= 1.2

        return min(base_score * multiplier, 10.0)

    def to_report_format(self) -> str:
        """Generate a formatted report of the attack chain."""
        steps_text = "\n".join([
            f"  {step.step_number}. [{step.vulnerability_type}] {step.action}\n"
            f"     → Output: {step.output_description}"
            for step in self.steps
        ])

        return f"""
## Attack Chain: {self.name}

**Type:** {self.chain_type.value}
**Impact:** {self.impact.value.upper()}
**Complexity:** {self.complexity.value}
**Combined Severity:** {self.combined_severity.upper()}

### Description
{self.description}

### Attack Steps
{steps_text}

### Final Objective
{self.final_objective}

### Business Impact
{self.business_impact}

### AI Reasoning
{self.ai_reasoning}

### Remediation
**Breaking Point:** {self.breaking_point}

{chr(10).join(f"- {step}" for step in self.remediation_steps)}
"""


class AttackChainAnalysis(BaseModel):
    """Results of attack chain analysis."""

    total_findings_analyzed: int = 0
    chains_discovered: int = 0
    chains: List[AttackChain] = Field(default_factory=list)

    # Severity distribution of chains
    critical_chains: int = 0
    high_chains: int = 0
    medium_chains: int = 0

    # Most impactful chain
    highest_impact_chain: Optional[str] = None
    highest_impact_score: float = 0.0

    # Analysis metadata
    analysis_duration_seconds: float = 0.0
    llm_tokens_used: int = 0

    def get_summary(self) -> str:
        """Get a summary of the chain analysis."""
        return f"""
Attack Chain Analysis Summary:
- Findings Analyzed: {self.total_findings_analyzed}
- Chains Discovered: {self.chains_discovered}
- Critical Chains: {self.critical_chains}
- High Chains: {self.high_chains}
- Medium Chains: {self.medium_chains}
- Highest Impact: {self.highest_impact_chain} (score: {self.highest_impact_score:.1f})
"""
