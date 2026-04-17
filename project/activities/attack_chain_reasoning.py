"""
Attack Chain Reasoning Activity.

This module implements LLM-based vulnerability correlation to discover
attack chains - sequences of vulnerabilities that can be combined for
greater impact than any single vulnerability alone.

This is a key differentiator for zero-day-like discovery through
creative AI reasoning.
"""
import asyncio
import json
import os
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from openai import AsyncOpenAI
from temporalio import activity

from agentex.lib.utils.logging import make_logger
from agentex.lib import adk
from agentex.types.text_content import TextContent

from project.models.attack_chain import (
    AttackChain,
    AttackChainAnalysis,
    ChainComplexity,
    ChainImpact,
    ChainStep,
    ChainType,
)

logger = make_logger(__name__)


# Common attack chain patterns for LLM guidance
CHAIN_PATTERNS = """
Common Attack Chain Patterns to Look For:

1. **IDOR + Info Disclosure → Account Takeover**
   - IDOR exposes user ID/email
   - Password reset uses predictable tokens
   - Combine to take over any account

2. **XSS + CSRF → Privileged Action Execution**
   - XSS allows arbitrary JavaScript execution
   - CSRF token is predictable or missing
   - Combine to perform actions as victim

3. **SSRF + Internal Service → RCE/Data Breach**
   - SSRF allows internal network access
   - Internal service has known vulnerabilities
   - Chain to access sensitive data or execute code

4. **SQL Injection + Hash Cracking → Full DB Compromise**
   - SQLi extracts password hashes
   - Weak hashing algorithm (MD5/SHA1)
   - Crack hashes for full account access

5. **Path Traversal + Config File → Credential Theft**
   - LFI reads arbitrary files
   - Config files contain credentials
   - Use credentials for privileged access

6. **Authentication Bypass + Admin Panel → Full Control**
   - Bypass authentication check
   - Access admin functionality
   - Full application control

7. **Open Redirect + OAuth → Token Theft**
   - Open redirect on trusted domain
   - OAuth callback manipulation
   - Steal authentication tokens

8. **XXE + SSRF → Internal Network Mapping**
   - XXE allows external entity loading
   - Use to probe internal network
   - Map internal services for further exploitation

9. **Race Condition + Balance Manipulation → Financial Fraud**
   - TOCTOU vulnerability in transactions
   - Exploit timing window
   - Duplicate transactions or bypass limits

10. **Subdomain Takeover + Cookie Scope → Session Hijacking**
    - Unclaimed subdomain
    - Cookies scoped to parent domain
    - Hijack sessions via malicious subdomain
"""


CHAIN_REASONING_PROMPT = """You are a world-class penetration tester and security researcher analyzing vulnerability findings to discover ATTACK CHAINS.

Attack chains are sequences of vulnerabilities that, when combined, achieve a greater impact than any single vulnerability alone. This is how real attackers think - they chain multiple weaknesses together.

## Your Task

Analyze these vulnerability findings and identify ALL possible attack chains:

{findings_json}

## Technologies & Context
{context}

## Chain Patterns Reference
{chain_patterns}

## Instructions

1. **Think Like an Attacker**: How would you combine these findings to maximize impact?
2. **Consider Data Flow**: What data from one vulnerability can feed into another?
3. **Look for Privilege Escalation Paths**: How can low-privilege access become high-privilege?
4. **Consider Business Logic**: What business-critical actions could an attacker perform?
5. **Be Creative**: Look for non-obvious combinations that a scanner wouldn't find.

## Output Format

Return a JSON array of attack chains. Each chain should have:
```json
[
  {{
    "name": "Descriptive name of the chain",
    "chain_type": "account_takeover|privilege_escalation|data_exfiltration|remote_code_execution|authentication_bypass|custom",
    "combined_severity": "critical|high|medium",
    "complexity": "trivial|low|medium|high|expert",
    "impact": "critical|high|medium|low",
    "description": "Clear description of the attack chain",
    "steps": [
      {{
        "step_number": 1,
        "vulnerability_name": "Name of the vulnerability used",
        "vulnerability_type": "IDOR|XSS|SQLi|SSRF|etc",
        "action": "What the attacker does in this step",
        "objective": "What this step achieves",
        "output_data": "Data obtained that feeds into next step",
        "output_description": "Description of the output"
      }}
    ],
    "final_objective": "What the complete chain achieves",
    "business_impact": "Real-world business impact",
    "reasoning": "Your reasoning about why this chain works and why it's impactful",
    "breaking_point": "Which vulnerability to fix first to break the chain",
    "remediation_steps": ["Step 1", "Step 2"],
    "requires_authentication": true|false,
    "requires_user_interaction": true|false,
    "confidence_score": 0.0-1.0
  }}
]
```

If no meaningful chains are found, return an empty array: []

IMPORTANT:
- Only include chains where the combination is MORE impactful than individual vulnerabilities
- Focus on realistic, exploitable chains
- Prioritize critical and high-impact chains
- Include your reasoning for why each chain works

Return ONLY the JSON array, no other text.
"""


async def call_llm_for_chains(prompt: str, max_tokens: int = 4000) -> str:
    """Call LLM API for chain reasoning using OpenAI SDK."""
    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    model = os.environ.get("OPENAI_MODEL", "gpt-4")

    if not api_key:
        raise ValueError("OPENAI_API_KEY not set")

    # Use OpenAI SDK for LLM calls
    client = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=120.0,
    )

    response = await client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": "You are an expert security researcher specializing in attack chain analysis. You think creatively about how vulnerabilities can be combined for maximum impact. Always respond with valid JSON.",
            },
            {"role": "user", "content": prompt},
        ],
        temperature=0.7,  # Slightly creative for novel chain discovery
        max_tokens=max_tokens,
    )

    return response.choices[0].message.content


def parse_chain_response(response: str) -> List[Dict[str, Any]]:
    """Parse LLM response to extract attack chains."""
    # Try to extract JSON from response
    try:
        # First try direct JSON parse
        return json.loads(response)
    except json.JSONDecodeError:
        pass

    # Try to find JSON array in response
    json_match = re.search(r'\[[\s\S]*\]', response)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

    logger.warning(f"Could not parse chain response: {response[:200]}")
    return []


def findings_to_json(findings: List[Dict[str, Any]]) -> str:
    """Convert findings to JSON format for LLM."""
    simplified = []
    for i, f in enumerate(findings, 1):
        simplified.append({
            "id": f.get("id", str(i)),
            "type": f.get("type", f.get("vulnerability_type", "unknown")),
            "name": f.get("title", f.get("name", "Unknown")),
            "severity": f.get("severity", "medium"),
            "url": f.get("url", f.get("affected_url", "")),
            "parameter": f.get("parameter", f.get("affected_parameter", "")),
            "description": f.get("description", "")[:200],
            "evidence": str(f.get("evidence", ""))[:200],
        })
    return json.dumps(simplified, indent=2)


def build_context(technologies: List[str], scope: Dict[str, Any]) -> str:
    """Build context string for LLM."""
    tech_str = ", ".join(technologies) if technologies else "Unknown"
    domains = scope.get("domains", [])
    domain_str = ", ".join(domains[:5]) if domains else "Unknown"

    return f"""
Technologies Detected: {tech_str}
Target Domains: {domain_str}
"""


def create_attack_chain_from_dict(chain_data: Dict[str, Any]) -> AttackChain:
    """Create AttackChain model from parsed dict."""
    # Map chain type
    chain_type_map = {
        "account_takeover": ChainType.ACCOUNT_TAKEOVER,
        "privilege_escalation": ChainType.PRIVILEGE_ESCALATION,
        "data_exfiltration": ChainType.DATA_EXFILTRATION,
        "remote_code_execution": ChainType.REMOTE_CODE_EXECUTION,
        "authentication_bypass": ChainType.AUTHENTICATION_BYPASS,
        "lateral_movement": ChainType.LATERAL_MOVEMENT,
        "network_pivot": ChainType.NETWORK_PIVOT,
        "denial_of_service": ChainType.DENIAL_OF_SERVICE,
    }

    complexity_map = {
        "trivial": ChainComplexity.TRIVIAL,
        "low": ChainComplexity.LOW,
        "medium": ChainComplexity.MEDIUM,
        "high": ChainComplexity.HIGH,
        "expert": ChainComplexity.EXPERT,
    }

    impact_map = {
        "critical": ChainImpact.CRITICAL,
        "high": ChainImpact.HIGH,
        "medium": ChainImpact.MEDIUM,
        "low": ChainImpact.LOW,
    }

    # Create steps
    steps = []
    for step_data in chain_data.get("steps", []):
        step = ChainStep(
            step_number=step_data.get("step_number", 0),
            vulnerability_name=step_data.get("vulnerability_name", ""),
            vulnerability_type=step_data.get("vulnerability_type", ""),
            action=step_data.get("action", ""),
            objective=step_data.get("objective", ""),
            output_data=step_data.get("output_data", ""),
            output_description=step_data.get("output_description", ""),
        )
        steps.append(step)

    # Create chain
    chain = AttackChain(
        id=str(uuid.uuid4()),
        name=chain_data.get("name", "Unknown Chain"),
        description=chain_data.get("description", ""),
        chain_type=chain_type_map.get(
            chain_data.get("chain_type", "custom"), ChainType.CUSTOM
        ),
        complexity=complexity_map.get(
            chain_data.get("complexity", "medium"), ChainComplexity.MEDIUM
        ),
        impact=impact_map.get(
            chain_data.get("impact", "medium"), ChainImpact.MEDIUM
        ),
        combined_severity=chain_data.get("combined_severity", "medium"),
        steps=steps,
        total_steps=len(steps),
        vulnerability_names=[s.vulnerability_name for s in steps],
        final_objective=chain_data.get("final_objective", ""),
        business_impact=chain_data.get("business_impact", ""),
        ai_reasoning=chain_data.get("reasoning", ""),
        confidence_score=chain_data.get("confidence_score", 0.7),
        breaking_point=chain_data.get("breaking_point", ""),
        remediation_steps=chain_data.get("remediation_steps", []),
        requires_authentication=chain_data.get("requires_authentication", False),
        requires_user_interaction=chain_data.get("requires_user_interaction", False),
        discovered_at=datetime.utcnow(),
        discovered_by="ai_chain_reasoner",
    )

    return chain


@activity.defn(name="analyze_attack_chains_activity")
async def analyze_attack_chains_activity(
    findings: List[Dict[str, Any]],
    technologies: List[str],
    scope: Dict[str, Any],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Analyze findings using LLM to discover attack chains.

    This is the core activity for creative AI-driven vulnerability correlation.
    The LLM reasons about how individual findings can be combined into
    high-impact attack chains.
    """
    logger.info(f"Analyzing {len(findings)} findings for attack chains")
    start_time = datetime.utcnow()

    if not findings or len(findings) < 2:
        logger.info("Not enough findings for chain analysis (need at least 2)")
        return {
            "chains": [],
            "total_findings_analyzed": len(findings),
            "chains_discovered": 0,
            "message": "Need at least 2 findings for chain analysis",
        }

    # Notify UI
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🔗 Attack Chain Reasoning Started

**Analyzing:** {len(findings)} vulnerability findings
**Objective:** Discover how vulnerabilities can be chained for greater impact

The AI will reason about:
- Privilege escalation paths
- Account takeover scenarios
- Data exfiltration chains
- Authentication bypass combinations

---""",
            ),
            trace_id=trace_id,
        )

    try:
        # Prepare prompt
        findings_json = findings_to_json(findings)
        context = build_context(technologies, scope)

        prompt = CHAIN_REASONING_PROMPT.format(
            findings_json=findings_json,
            context=context,
            chain_patterns=CHAIN_PATTERNS,
        )

        # Call LLM
        logger.info("Calling LLM for chain reasoning...")
        llm_response = await call_llm_for_chains(prompt)
        logger.info(f"LLM response received: {len(llm_response)} chars")

        # Parse response
        chain_dicts = parse_chain_response(llm_response)
        logger.info(f"Parsed {len(chain_dicts)} attack chains")

        # Create AttackChain objects
        chains: List[AttackChain] = []
        for chain_data in chain_dicts:
            try:
                chain = create_attack_chain_from_dict(chain_data)
                chains.append(chain)
            except Exception as e:
                logger.warning(f"Failed to create chain from data: {e}")
                continue

        # Sort by impact
        chains.sort(key=lambda c: c.get_risk_score(), reverse=True)

        # Calculate statistics
        critical_chains = sum(1 for c in chains if c.combined_severity == "critical")
        high_chains = sum(1 for c in chains if c.combined_severity == "high")
        medium_chains = sum(1 for c in chains if c.combined_severity == "medium")

        duration = (datetime.utcnow() - start_time).total_seconds()

        # Stream results to UI
        if task_id and chains:
            for chain in chains[:5]:  # Show top 5 chains
                severity_emoji = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                }.get(chain.combined_severity, "⚪")

                steps_text = "\n".join([
                    f"   {s.step_number}. **[{s.vulnerability_type}]** {s.action}"
                    for s in chain.steps
                ])

                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"""{severity_emoji} **Attack Chain Discovered: {chain.name}**

**Type:** {chain.chain_type.value}
**Combined Severity:** {chain.combined_severity.upper()}
**Impact:** {chain.impact.value}
**Confidence:** {chain.confidence_score:.0%}

**Attack Steps:**
{steps_text}

**Final Objective:** {chain.final_objective}

**Business Impact:** {chain.business_impact}

**AI Reasoning:** {chain.ai_reasoning[:300]}{'...' if len(chain.ai_reasoning) > 300 else ''}

**Breaking Point:** Fix {chain.breaking_point} to break this chain.

---""",
                    ),
                    trace_id=trace_id,
                )

        # Summary notification
        if task_id:
            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content=f"""### 🔗 Attack Chain Analysis Complete

**Results:**
- Findings Analyzed: {len(findings)}
- Chains Discovered: {len(chains)}
- 🔴 Critical Chains: {critical_chains}
- 🟠 High Chains: {high_chains}
- 🟡 Medium Chains: {medium_chains}
- Analysis Time: {duration:.1f}s

{f"**Highest Impact Chain:** {chains[0].name}" if chains else "No chains discovered"}

---""",
                ),
                trace_id=trace_id,
            )

        # Return results
        return {
            "chains": [
                {
                    "id": c.id,
                    "name": c.name,
                    "chain_type": c.chain_type.value,
                    "combined_severity": c.combined_severity,
                    "impact": c.impact.value,
                    "complexity": c.complexity.value,
                    "steps": [
                        {
                            "step_number": s.step_number,
                            "vulnerability_name": s.vulnerability_name,
                            "vulnerability_type": s.vulnerability_type,
                            "action": s.action,
                            "objective": s.objective,
                        }
                        for s in c.steps
                    ],
                    "final_objective": c.final_objective,
                    "business_impact": c.business_impact,
                    "ai_reasoning": c.ai_reasoning,
                    "confidence_score": c.confidence_score,
                    "breaking_point": c.breaking_point,
                    "remediation_steps": c.remediation_steps,
                    "risk_score": c.get_risk_score(),
                }
                for c in chains
            ],
            "total_findings_analyzed": len(findings),
            "chains_discovered": len(chains),
            "critical_chains": critical_chains,
            "high_chains": high_chains,
            "medium_chains": medium_chains,
            "analysis_duration_seconds": duration,
        }

    except Exception as e:
        logger.error(f"Attack chain analysis failed: {e}")

        if task_id:
            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content=f"**⚠️ Attack chain analysis error:** {str(e)[:100]}",
                ),
                trace_id=trace_id,
            )

        return {
            "chains": [],
            "total_findings_analyzed": len(findings),
            "chains_discovered": 0,
            "error": str(e),
        }


@activity.defn(name="reason_about_chain_exploitability_activity")
async def reason_about_chain_exploitability_activity(
    chain: Dict[str, Any],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Deep-dive reasoning about a specific attack chain's exploitability.

    This activity takes a discovered chain and reasons more deeply about:
    - Exact exploitation steps
    - Required conditions
    - Potential variations
    - Proof of concept outline
    """
    logger.info(f"Deep reasoning about chain: {chain.get('name', 'Unknown')}")

    prompt = f"""You are creating a detailed exploitation analysis for this attack chain:

Chain: {chain.get('name', 'Unknown')}
Type: {chain.get('chain_type', 'unknown')}
Steps: {json.dumps(chain.get('steps', []), indent=2)}

Provide:
1. **Detailed Exploitation Steps**: Exact commands/requests for each step
2. **Prerequisites**: What must be true for this to work
3. **Variations**: Alternative approaches that could work
4. **Detection Indicators**: What would defenders see
5. **Proof of Concept Outline**: High-level PoC script structure

Be specific and technical. This is for authorized security testing.

Return as JSON:
{{
  "detailed_steps": ["Step 1 with exact details", "Step 2..."],
  "prerequisites": ["Prereq 1", "Prereq 2"],
  "variations": ["Variation 1", "Variation 2"],
  "detection_indicators": ["Indicator 1", "Indicator 2"],
  "poc_outline": "High-level PoC description",
  "estimated_success_rate": 0.0-1.0,
  "additional_insights": "Any other relevant observations"
}}
"""

    try:
        response = await call_llm_for_chains(prompt, max_tokens=2000)
        result = json.loads(response)

        if task_id:
            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content=f"""### 🔬 Deep Analysis: {chain.get('name', 'Unknown')}

**Estimated Success Rate:** {result.get('estimated_success_rate', 0) * 100:.0f}%

**Prerequisites:**
{chr(10).join(f"- {p}" for p in result.get('prerequisites', [])[:5])}

**Variations:**
{chr(10).join(f"- {v}" for v in result.get('variations', [])[:3])}

**Detection Indicators:**
{chr(10).join(f"- {d}" for d in result.get('detection_indicators', [])[:3])}

---""",
                ),
                trace_id=trace_id,
            )

        return result

    except Exception as e:
        logger.error(f"Deep chain reasoning failed: {e}")
        return {"error": str(e)}


@activity.defn(name="generate_chain_poc_activity")
async def generate_chain_poc_activity(
    chain: Dict[str, Any],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Generate a proof-of-concept script for an attack chain.

    This creates an automated PoC that can demonstrate the chain
    in a controlled environment.
    """
    logger.info(f"Generating PoC for chain: {chain.get('name', 'Unknown')}")

    prompt = f"""Generate a Python proof-of-concept script for this attack chain:

Chain: {chain.get('name', 'Unknown')}
Type: {chain.get('chain_type', 'unknown')}
Steps: {json.dumps(chain.get('steps', []), indent=2)}
Final Objective: {chain.get('final_objective', 'Unknown')}

Requirements:
1. Use the `requests` library for HTTP
2. Include clear comments explaining each step
3. Add error handling
4. Make target URL configurable
5. Add a safety check to confirm authorization
6. Print clear output showing the chain progression

Return ONLY the Python code, no markdown formatting.
"""

    try:
        response = await call_llm_for_chains(prompt, max_tokens=3000)

        # Clean up response (remove markdown if present)
        code = response.strip()
        if code.startswith("```python"):
            code = code[9:]
        if code.startswith("```"):
            code = code[3:]
        if code.endswith("```"):
            code = code[:-3]
        code = code.strip()

        if task_id:
            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content=f"""### 🧪 PoC Generated: {chain.get('name', 'Unknown')}

A proof-of-concept script has been generated for authorized testing.

**⚠️ Warning:** Only use this PoC against systems you have explicit authorization to test.

```python
{code[:1000]}{'...' if len(code) > 1000 else ''}
```

---""",
                ),
                trace_id=trace_id,
            )

        return {
            "chain_name": chain.get("name", "Unknown"),
            "poc_script": code,
            "language": "python",
            "generated_at": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"PoC generation failed: {e}")
        return {"error": str(e)}
