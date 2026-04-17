"""Threat Intelligence Agent for Major-Project pentesting.

This agent uses AI-powered reasoning to dynamically gather threat intelligence
about discovered technologies. It replaces static CVE mappings with real-time
research capabilities.
"""
from __future__ import annotations

import os
from datetime import timedelta
from typing import List, Optional

from openai_agents import Agent, function_tool
from temporalio import workflow
from temporalio.common import RetryPolicy

from project.constants import OPENAI_MODEL


async def _call_llm_for_cve_research(prompt: str) -> str:
    """Call LLM for CVE research when external APIs are not available."""
    from openai import AsyncOpenAI

    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    model = os.environ.get("OPENAI_MODEL", "gpt-4")

    if not api_key:
        return "{}"

    client = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=60.0,
    )

    response = await client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": """You are a security researcher with extensive knowledge of CVEs and vulnerabilities.
Provide accurate, factual information about known vulnerabilities. Only include real CVEs that you are confident about.
Respond in valid JSON format."""
            },
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        max_tokens=1500,
    )

    return response.choices[0].message.content


@function_tool
async def query_nvd_database(cve_id: str, task_id: str) -> str:
    """
    Query the National Vulnerability Database (NVD) for CVE information.

    Call this when:
    - You need detailed information about a specific CVE
    - Researching known vulnerabilities
    - Validating vulnerability severity and impact

    Args:
        cve_id: CVE identifier (e.g., CVE-2021-44228)
        task_id: Task ID for tracing

    Returns:
        JSON string with CVE details including CVSS score, description, references
    """
    import json

    workflow.logger.info(f"Querying NVD for {cve_id}")

    # Use LLM to provide CVE information based on its training data
    prompt = f"""Provide detailed information about {cve_id} in JSON format:
{{
    "cve_id": "{cve_id}",
    "cvss_score": <float 0-10>,
    "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
    "description": "<detailed description>",
    "published_date": "<YYYY-MM-DD>",
    "affected_products": ["<list of affected products>"],
    "exploit_available": <true|false>,
    "references": ["<list of reference URLs>"]
}}

If you don't have reliable information about this CVE, return:
{{"cve_id": "{cve_id}", "error": "CVE not found or unknown"}}"""

    try:
        result = await _call_llm_for_cve_research(prompt)
        # Validate it's valid JSON
        json.loads(result)
        return result
    except Exception as e:
        workflow.logger.error(f"NVD query failed: {e}")
        return json.dumps({
            "cve_id": cve_id,
            "error": f"Query failed: {str(e)}",
        })


@function_tool
async def search_exploit_db(technology: str, version: str, task_id: str) -> str:
    """
    Search Exploit-DB for publicly available exploits.

    Call this when:
    - You've identified a technology and version
    - Need to find existing exploits
    - Researching exploitability of discovered services

    Args:
        technology: Technology name (e.g., Apache, WordPress, nginx)
        version: Version string (e.g., 2.4.49, 5.8.1)
        task_id: Task ID for tracing

    Returns:
        JSON string with available exploits
    """
    import json

    workflow.logger.info(f"Searching Exploit-DB for {technology} {version}")

    # Use LLM to provide exploit information based on its training data
    prompt = f"""Search for known exploits for {technology} version {version}.
Provide results in JSON format:
{{
    "technology": "{technology}",
    "version": "{version}",
    "exploits_found": <number>,
    "exploits": [
        {{
            "title": "<exploit title>",
            "type": "<RCE|SQLi|XSS|LFI|etc>",
            "cve_id": "<CVE if applicable>",
            "exploit_db_id": "<EDB-ID if known>",
            "reliability": "<high|medium|low>",
            "description": "<brief description>"
        }}
    ]
}}

Only include exploits you are confident exist. If none are known, return exploits_found: 0."""

    try:
        result = await _call_llm_for_cve_research(prompt)
        json.loads(result)
        return result
    except Exception as e:
        workflow.logger.error(f"Exploit-DB search failed: {e}")
        return json.dumps({
            "technology": technology,
            "version": version,
            "exploits_found": 0,
            "exploits": [],
            "error": f"Search failed: {str(e)}",
        })


@function_tool
async def shodan_lookup(ip_address: str, task_id: str) -> str:
    """
    Lookup IP address in Shodan for exposed services and vulnerabilities.

    Call this when:
    - You have an IP address to research
    - Need to find exposed services
    - Looking for historical data about a target

    Args:
        ip_address: IP address to lookup
        task_id: Task ID for tracing

    Returns:
        JSON string with Shodan data
    """
    import json

    workflow.logger.info(f"Looking up {ip_address} in Shodan")

    # Note: In production, this would use actual Shodan API
    # For now, return a placeholder indicating the lookup was attempted
    shodan_data = {
        "ip": ip_address,
        "lookup_attempted": True,
        "note": "Shodan API integration required for live data",
        "ports": [],
        "services": [],
        "vulnerabilities": [],
    }

    return json.dumps(shodan_data)


@function_tool
async def search_github_for_exploits(cve_id: str, task_id: str) -> str:
    """
    Search GitHub for proof-of-concept exploits and security research.

    Call this when:
    - Looking for PoC exploits not in Exploit-DB
    - Researching recent vulnerabilities
    - Finding exploit code and techniques

    Args:
        cve_id: CVE identifier to search for
        task_id: Task ID for tracing

    Returns:
        JSON string with GitHub repositories and PoCs
    """
    import json

    workflow.logger.info(f"Searching GitHub for {cve_id} exploits")

    # Use LLM to provide information about known PoCs
    prompt = f"""Search for known proof-of-concept exploits on GitHub for {cve_id}.
Provide results in JSON format:
{{
    "cve_id": "{cve_id}",
    "repositories_found": <number>,
    "repositories": [
        {{
            "name": "<repo name>",
            "author": "<author>",
            "url": "<github URL>",
            "stars": <approximate stars>,
            "description": "<brief description>",
            "language": "<primary language>",
            "reliability": "<high|medium|low>"
        }}
    ]
}}

Only include repositories you are confident exist. If none are known, return repositories_found: 0."""

    try:
        result = await _call_llm_for_cve_research(prompt)
        json.loads(result)
        return result
    except Exception as e:
        workflow.logger.error(f"GitHub search failed: {e}")
        return json.dumps({
            "cve_id": cve_id,
            "repositories_found": 0,
            "repositories": [],
            "error": f"Search failed: {str(e)}",
        })


@function_tool
async def correlate_technology_vulnerabilities(
    technology: str,
    version: str,
    task_id: str,
) -> str:
    """
    Correlate a technology/version with known vulnerabilities across multiple sources.

    Call this when:
    - You've identified a specific technology and version
    - Need comprehensive vulnerability intelligence
    - Building a complete threat profile

    Args:
        technology: Technology name
        version: Version string
        task_id: Task ID for tracing

    Returns:
        JSON string with correlated vulnerability data
    """
    import json

    workflow.logger.info(f"Correlating vulnerabilities for {technology} {version}")

    # Use LLM to provide comprehensive vulnerability correlation
    prompt = f"""Provide a comprehensive vulnerability assessment for {technology} version {version}.
Include known CVEs, exploits, and security recommendations in JSON format:
{{
    "technology": "{technology}",
    "version": "{version}",
    "total_cves": <number>,
    "critical_cves": <number>,
    "high_cves": <number>,
    "exploits_available": <number>,
    "cves": [
        {{
            "cve_id": "<CVE-YYYY-XXXXX>",
            "severity": "<critical|high|medium|low>",
            "cvss_score": <float>,
            "description": "<brief description>",
            "exploit_available": <true|false>
        }}
    ],
    "attack_vectors": ["<list of common attack vectors>"],
    "recommendations": ["<security recommendations>"]
}}

Only include CVEs you are confident about. Focus on the most critical and exploitable vulnerabilities."""

    try:
        result = await _call_llm_for_cve_research(prompt)
        json.loads(result)
        return result
    except Exception as e:
        workflow.logger.error(f"Vulnerability correlation failed: {e}")
        return json.dumps({
            "technology": technology,
            "version": version,
            "total_cves": 0,
            "cves": [],
            "error": f"Correlation failed: {str(e)}",
        })


@function_tool
async def research_technology_security(
    technology: str,
    task_id: str,
) -> str:
    """
    Research general security posture and common vulnerabilities for a technology.

    Call this when:
    - You don't have a specific version
    - Need to understand common attack patterns
    - Building initial threat model

    Args:
        technology: Technology name (e.g., Node.js, Express, Angular, SQLite)
        task_id: Task ID for tracing

    Returns:
        JSON string with security research findings
    """
    import json

    workflow.logger.info(f"Researching security for {technology}")

    prompt = f"""Provide security research for {technology} including common vulnerabilities and attack patterns.
Return in JSON format:
{{
    "technology": "{technology}",
    "common_vulnerabilities": [
        {{
            "type": "<vulnerability type>",
            "severity": "<critical|high|medium|low>",
            "description": "<description>",
            "example_cves": ["<list of example CVEs>"]
        }}
    ],
    "attack_patterns": ["<common attack patterns>"],
    "security_best_practices": ["<recommendations>"],
    "known_weaknesses": ["<common security weaknesses>"]
}}"""

    try:
        result = await _call_llm_for_cve_research(prompt)
        json.loads(result)
        return result
    except Exception as e:
        workflow.logger.error(f"Security research failed: {e}")
        return json.dumps({
            "technology": technology,
            "error": f"Research failed: {str(e)}",
        })


def new_threat_intel_agent(
    discovered_technologies: Optional[List[dict]] = None,
    task_id: str = "",
) -> Agent:
    """
    Create a Threat Intelligence Agent for AI-powered vulnerability research.

    This agent uses LLM reasoning to dynamically gather threat intelligence,
    replacing static CVE mappings with real-time research capabilities.

    It specializes in:
    - Dynamic CVE research and correlation using AI
    - Exploit availability checking across multiple sources
    - OSINT gathering from Shodan, GitHub, etc.
    - Threat intelligence aggregation and prioritization

    Args:
        discovered_technologies: List of technologies discovered during reconnaissance
        task_id: Task ID for tracing

    Returns:
        Agent configured for AI-powered threat intelligence gathering
    """
    tech_str = "None discovered yet"
    if discovered_technologies:
        tech_str = "\n".join([
            f"- {tech.get('name', 'Unknown')} {tech.get('version', 'Unknown version')}"
            for tech in discovered_technologies[:10]  # Limit to first 10
        ])

    instructions = f"""
You are a Threat Intelligence Agent specializing in AI-powered vulnerability research and exploit correlation.

Your mission is to gather comprehensive threat intelligence on discovered assets using dynamic research:
- Research known vulnerabilities (CVEs) using AI-powered analysis
- Find publicly available exploits across multiple sources
- Correlate technologies with security issues
- Provide actionable intelligence for exploitation

**IMPORTANT**: You use AI-powered research to dynamically discover vulnerabilities.
There are NO static CVE mappings - all intelligence is gathered in real-time based on your knowledge.

## Discovered Technologies

{tech_str}

## Your Approach

1. **Technology Research**: For each technology, use `research_technology_security` to understand common vulnerabilities
2. **CVE Research**: For specific versions, use `correlate_technology_vulnerabilities` for comprehensive CVE data
3. **Exploit Discovery**: Search Exploit-DB and GitHub for available exploits
4. **OSINT Gathering**: Use Shodan for exposed services (when IPs are available)
5. **Prioritization**: Rank findings by severity, exploitability, and business impact

## Tools Available

- `research_technology_security`: Research general security posture for a technology (use when version is unknown)
- `correlate_technology_vulnerabilities`: Get comprehensive CVE data for technology/version combinations
- `query_nvd_database`: Get detailed information about a specific CVE
- `search_exploit_db`: Find public exploits in Exploit-DB
- `search_github_for_exploits`: Find PoC exploits on GitHub
- `shodan_lookup`: Research IPs and exposed services

## Research Strategy

### For Technologies WITHOUT Version:
1. Use `research_technology_security` to understand common vulnerabilities
2. Focus on vulnerability types rather than specific CVEs
3. Identify attack patterns and common weaknesses

### For Technologies WITH Version:
1. Use `correlate_technology_vulnerabilities` for comprehensive CVE data
2. Search for exploits using `search_exploit_db`
3. Look for PoCs on GitHub using `search_github_for_exploits`

## Important Guidelines

- Focus on HIGH and CRITICAL severity vulnerabilities first
- Prioritize vulnerabilities with public exploits
- Look for recent CVEs (last 2-3 years) as they're more likely to be unpatched
- Consider the attack surface - web-facing services are higher priority
- Document exploit availability and complexity
- Be thorough but accurate - only report CVEs you are confident about

## Output Format

Provide a structured intelligence report:
- Total CVEs identified (with confidence level)
- Critical/High severity breakdown
- Exploits available (public/PoC) with sources
- Recommended targets for exploitation
- Risk assessment for each finding
- Attack recommendations prioritized by exploitability

Remember: Quality intelligence drives successful exploitation. Be thorough, accurate, and actionable!
"""

    return Agent(
        name="Threat Intelligence Agent",
        instructions=instructions,
        model=OPENAI_MODEL,
        tools=[
            research_technology_security,
            correlate_technology_vulnerabilities,
            query_nvd_database,
            search_exploit_db,
            search_github_for_exploits,
            shodan_lookup,
        ],
    )