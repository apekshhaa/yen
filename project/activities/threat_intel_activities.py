"""
Threat Intelligence Activities for Major-Project AI Pentester.

This module provides activities that use the threat_intel_agent to dynamically
gather CVE information, exploit availability, and OSINT data based on
discovered technologies.
"""
import json
import os
from typing import Any, Dict, List, Optional

from temporalio import activity

from agentex.lib.utils.logging import make_logger
from agentex.lib import adk
from agentex.types.text_content import TextContent
from agentex.types.tool_request_content import ToolRequestContent
from agentex.types.tool_response_content import ToolResponseContent

logger = make_logger(__name__)


async def call_llm_for_threat_intel(prompt: str, system_prompt: str) -> str:
    """Call LLM API for threat intelligence analysis."""
    from openai import AsyncOpenAI

    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    model = os.environ.get("OPENAI_MODEL", "gpt-4")

    if not api_key:
        raise ValueError("OPENAI_API_KEY not set")

    client = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=90.0,
    )

    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,  # Lower temperature for more factual responses
        max_tokens=2000,
    )

    return response.choices[0].message.content


THREAT_INTEL_SYSTEM_PROMPT = """You are a Threat Intelligence Agent specializing in vulnerability research and exploit correlation.

Your mission is to gather comprehensive threat intelligence on discovered technologies:
- Research known vulnerabilities (CVEs)
- Find publicly available exploits
- Correlate technologies with security issues
- Provide actionable intelligence for exploitation

## Your Approach

1. **CVE Research**: For each technology/version, identify known CVEs
2. **Exploit Discovery**: Identify if public exploits exist (Exploit-DB, GitHub PoCs)
3. **Severity Assessment**: Prioritize by CVSS score and exploitability
4. **OSINT Gathering**: Consider common misconfigurations and attack vectors

## Important Guidelines

- Focus on HIGH and CRITICAL severity vulnerabilities first
- Prioritize vulnerabilities with public exploits
- Look for recent CVEs (last 2-3 years) as they're more likely to be unpatched
- Consider the attack surface - web-facing services are higher priority
- Document exploit availability and complexity

## Output Format

You MUST respond with a valid JSON object containing:
{
    "cves": [
        {
            "cve_id": "CVE-YYYY-XXXXX",
            "technology": "technology name",
            "version": "affected version or 'multiple'",
            "severity": "critical|high|medium|low",
            "cvss_score": 9.8,
            "description": "Brief description of the vulnerability",
            "exploit_available": true|false,
            "exploit_source": "Exploit-DB|GitHub|Metasploit|None",
            "exploit_complexity": "easy|moderate|difficult",
            "remediation": "Brief remediation advice"
        }
    ],
    "exploits": [
        {
            "cve_id": "CVE-YYYY-XXXXX",
            "name": "Exploit name",
            "source": "Exploit-DB|GitHub|Metasploit",
            "url": "URL or reference",
            "type": "RCE|SQLi|XSS|LFI|etc",
            "reliability": "high|medium|low"
        }
    ],
    "osint_findings": [
        {
            "finding": "Description of OSINT finding",
            "relevance": "high|medium|low",
            "source": "Source of information"
        }
    ],
    "attack_recommendations": [
        {
            "priority": 1,
            "target": "technology or service",
            "vulnerability": "CVE or vulnerability type",
            "reason": "Why this should be prioritized"
        }
    ]
}

Be thorough and accurate. Only include CVEs that are real and relevant to the technologies provided.
"""


def parse_threat_intel_response(response: str) -> Dict[str, Any]:
    """Parse the LLM response to extract threat intelligence data."""
    import re

    # Try to extract JSON from the response
    try:
        # First, try direct JSON parsing
        return json.loads(response)
    except json.JSONDecodeError:
        pass

    # Try to find JSON block in markdown code blocks
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try to find raw JSON object
    json_match = re.search(r'\{[^{}]*"cves"[^{}]*\}', response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    # Return empty structure if parsing fails
    logger.warning("Failed to parse threat intel response, returning empty structure")
    return {
        "cves": [],
        "exploits": [],
        "osint_findings": [],
        "attack_recommendations": [],
    }


@activity.defn(name="run_threat_intel_agent_activity")
async def run_threat_intel_agent_activity(
    technologies: List[str],
    assets: List[Dict[str, Any]],
    task_id: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run the threat intelligence agent to gather CVE and exploit information.

    This activity uses an LLM to dynamically research vulnerabilities based on
    the discovered technologies, replacing the static CVE mapping approach.

    Args:
        technologies: List of technology names/versions discovered
        assets: List of discovered assets with their details
        task_id: Task ID for UI streaming
        trace_id: Trace ID for logging

    Returns:
        Dictionary containing CVEs, exploits, OSINT findings, and recommendations
    """
    logger.info(f"Starting threat intel agent for {len(technologies)} technologies")

    # Send heartbeat
    activity.heartbeat("Starting threat intelligence gathering")

    # Notify UI
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🔍 Threat Intelligence Agent Started

**Technologies to research:** {len(technologies)}
- {chr(10).join([f'`{t}`' for t in technologies[:10]])}
{'- ... and more' if len(technologies) > 10 else ''}

Researching CVEs, exploits, and OSINT data...""",
            ),
            trace_id=trace_id,
        )

    # Build the prompt with discovered technologies
    tech_list = "\n".join([f"- {tech}" for tech in technologies])

    # Extract additional context from assets
    services_info = []
    for asset in assets[:10]:  # Limit to first 10 assets
        host = asset.get("hostname") or asset.get("ip_address", "unknown")
        ports = asset.get("ports", [])
        services = asset.get("services", [])
        services_info.append(f"- {host}: ports {ports}, services: {services}")

    services_str = "\n".join(services_info) if services_info else "No detailed service information available"

    prompt = f"""Analyze the following discovered technologies and provide comprehensive threat intelligence:

## Discovered Technologies
{tech_list}

## Asset Information
{services_str}

## Task
1. Research known CVEs for each technology
2. Identify if public exploits exist
3. Provide OSINT findings relevant to these technologies
4. Recommend attack priorities based on severity and exploitability

Focus on:
- Critical and High severity vulnerabilities
- Vulnerabilities with public exploits
- Recent CVEs (2021-2024)
- Common misconfigurations

Respond with a JSON object containing cves, exploits, osint_findings, and attack_recommendations."""

    try:
        # Send tool request to UI
        tool_call_id = f"threat_intel_{hash(str(technologies))}"
        if task_id:
            await adk.messages.create(
                task_id=task_id,
                content=ToolRequestContent(
                    author="agent",
                    tool_call_id=tool_call_id,
                    name="threat_intel_research",
                    arguments={"technologies": technologies[:10]},
                ),
                trace_id=trace_id,
            )

        # Call LLM for threat intelligence
        activity.heartbeat("Calling LLM for threat intelligence analysis")
        llm_response = await call_llm_for_threat_intel(prompt, THREAT_INTEL_SYSTEM_PROMPT)

        # Parse the response
        activity.heartbeat("Parsing threat intelligence response")
        intel_data = parse_threat_intel_response(llm_response)

        # Extract results
        cves = intel_data.get("cves", [])
        exploits = intel_data.get("exploits", [])
        osint_findings = intel_data.get("osint_findings", [])
        attack_recommendations = intel_data.get("attack_recommendations", [])

        # Send tool response to UI
        if task_id:
            await adk.messages.create(
                task_id=task_id,
                content=ToolResponseContent(
                    author="agent",
                    tool_call_id=tool_call_id,
                    name="threat_intel_research",
                    content=f"Found {len(cves)} CVEs, {len(exploits)} exploits, {len(osint_findings)} OSINT findings",
                ),
                trace_id=trace_id,
            )

        # Stream detailed findings to UI
        if task_id and cves:
            # Group CVEs by severity
            critical_cves = [c for c in cves if c.get("severity") == "critical"]
            high_cves = [c for c in cves if c.get("severity") == "high"]

            cve_summary = ""
            if critical_cves:
                cve_summary += "\n**🔴 Critical CVEs:**\n"
                for cve in critical_cves[:5]:
                    exploit_badge = "⚡ Exploit Available" if cve.get("exploit_available") else ""
                    cve_summary += f"- `{cve.get('cve_id')}` - {cve.get('technology')} - {cve.get('description', '')[:100]}... {exploit_badge}\n"

            if high_cves:
                cve_summary += "\n**🟠 High CVEs:**\n"
                for cve in high_cves[:5]:
                    exploit_badge = "⚡ Exploit Available" if cve.get("exploit_available") else ""
                    cve_summary += f"- `{cve.get('cve_id')}` - {cve.get('technology')} - {cve.get('description', '')[:100]}... {exploit_badge}\n"

            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content=f"""### 📊 Threat Intelligence Results

**Summary:**
- 🔴 Critical CVEs: {len(critical_cves)}
- 🟠 High CVEs: {len(high_cves)}
- ⚡ Exploits Available: {len(exploits)}
- 🔎 OSINT Findings: {len(osint_findings)}
{cve_summary}""",
                ),
                trace_id=trace_id,
            )

        logger.info(f"Threat intel complete: {len(cves)} CVEs, {len(exploits)} exploits")

        return {
            "cves": cves,
            "exploits": exploits,
            "osint_findings": osint_findings,
            "attack_recommendations": attack_recommendations,
            "technologies_analyzed": len(technologies),
        }

    except Exception as e:
        logger.error(f"Threat intel agent failed: {e}")

        if task_id:
            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content=f"**⚠️ Threat Intelligence Error:** {str(e)[:200]}",
                ),
                trace_id=trace_id,
            )

        return {
            "cves": [],
            "exploits": [],
            "osint_findings": [],
            "attack_recommendations": [],
            "error": str(e),
        }


@activity.defn(name="correlate_vulnerabilities_activity")
async def correlate_vulnerabilities_activity(
    cves: List[Dict[str, Any]],
    exploits: List[Dict[str, Any]],
    assets: List[Dict[str, Any]],
    task_id: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Correlate discovered CVEs with assets to create actionable vulnerability records.

    This activity maps CVEs to specific assets based on their technologies,
    creating a prioritized list of vulnerabilities for the exploitation phase.

    Args:
        cves: List of CVEs from threat intelligence
        exploits: List of available exploits
        assets: List of discovered assets
        task_id: Task ID for UI streaming
        trace_id: Trace ID for logging

    Returns:
        Dictionary containing correlated vulnerabilities and prioritized targets
    """
    logger.info(f"Correlating {len(cves)} CVEs with {len(assets)} assets")

    activity.heartbeat("Correlating vulnerabilities with assets")

    vulnerabilities = []
    prioritized_targets = []

    # Create a map of exploits by CVE ID for quick lookup
    exploit_map = {}
    for exploit in exploits:
        cve_id = exploit.get("cve_id")
        if cve_id:
            if cve_id not in exploit_map:
                exploit_map[cve_id] = []
            exploit_map[cve_id].append(exploit)

    # Correlate CVEs with assets
    for cve in cves:
        cve_id = cve.get("cve_id", "")
        technology = cve.get("technology", "").lower()
        severity = cve.get("severity", "medium")

        # Find assets that have this technology
        for asset in assets:
            asset_techs = [t.lower() for t in asset.get("technologies", [])]
            host = asset.get("hostname") or asset.get("ip_address", "unknown")

            # Check if asset has the vulnerable technology
            if any(technology in tech for tech in asset_techs):
                vuln = {
                    "cve_id": cve_id,
                    "name": cve.get("description", cve_id)[:100],
                    "severity": severity,
                    "cvss_score": cve.get("cvss_score"),
                    "affected_asset": host,
                    "technology": cve.get("technology"),
                    "version": cve.get("version"),
                    "exploit_available": cve.get("exploit_available", False),
                    "exploit_source": cve.get("exploit_source"),
                    "exploit_complexity": cve.get("exploit_complexity"),
                    "remediation": cve.get("remediation"),
                    "exploits": exploit_map.get(cve_id, []),
                }
                vulnerabilities.append(vuln)

                # Add to prioritized targets if high severity with exploit
                if severity in ["critical", "high"] and cve.get("exploit_available"):
                    prioritized_targets.append({
                        "asset": host,
                        "cve_id": cve_id,
                        "severity": severity,
                        "exploit_complexity": cve.get("exploit_complexity", "unknown"),
                        "priority_score": 10 if severity == "critical" else 8,
                    })

    # Sort prioritized targets by priority score
    prioritized_targets.sort(key=lambda x: x.get("priority_score", 0), reverse=True)

    # Notify UI
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🎯 Vulnerability Correlation Complete

**Correlated Vulnerabilities:** {len(vulnerabilities)}
**Prioritized Targets:** {len(prioritized_targets)}

**Top Targets for Exploitation:**
{chr(10).join([f"- `{t['asset']}` - {t['cve_id']} ({t['severity'].upper()})" for t in prioritized_targets[:5]])}""",
            ),
            trace_id=trace_id,
        )

    logger.info(f"Correlation complete: {len(vulnerabilities)} vulnerabilities, {len(prioritized_targets)} prioritized targets")

    return {
        "vulnerabilities": vulnerabilities,
        "prioritized_targets": prioritized_targets,
        "total_cves": len(cves),
        "total_assets": len(assets),
    }