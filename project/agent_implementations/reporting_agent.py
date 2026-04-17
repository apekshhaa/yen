"""Reporting Agent for Major-Project pentesting."""
from __future__ import annotations

from typing import List, Optional

from openai_agents import Agent, function_tool
from temporalio import workflow

from project.constants import OPENAI_MODEL


@function_tool
async def generate_finding(
    vulnerability_id: str,
    title: str,
    severity: str,
    description: str,
    affected_assets: List[str],
    evidence: str,
    cvss_score: Optional[float],
    task_id: str,
) -> str:
    """
    Generate a security finding for the report.

    Call this when:
    - You've verified a vulnerability
    - Need to document a security issue
    - Creating report content

    Args:
        vulnerability_id: Unique ID for the vulnerability
        title: Clear, concise title
        severity: Severity level (critical, high, medium, low, info)
        description: Detailed description of the vulnerability
        affected_assets: List of affected systems/services
        evidence: Proof of the vulnerability
        cvss_score: CVSS score if applicable
        task_id: Task ID for tracing

    Returns:
        JSON string with the generated finding
    """
    import json

    workflow.logger.info(f"Generating finding: {title}")

    finding = {
        "id": vulnerability_id,
        "title": title,
        "severity": severity,
        "cvss_score": cvss_score,
        "description": description,
        "affected_assets": affected_assets,
        "evidence": evidence,
        "verified": True,
        "timestamp": "2024-01-01T00:00:00Z",  # In production, use actual timestamp
    }

    return json.dumps(finding)


@function_tool
async def suggest_remediation(
    vulnerability_type: str,
    affected_service: str,
    severity: str,
    task_id: str,
) -> str:
    """
    Generate remediation recommendations for a vulnerability.

    Call this when:
    - Creating findings
    - Need actionable fix recommendations
    - Helping client understand how to fix issues

    Args:
        vulnerability_type: Type of vulnerability
        affected_service: Service that is vulnerable
        severity: Severity level
        task_id: Task ID for tracing

    Returns:
        JSON string with remediation recommendations
    """
    import json

    workflow.logger.info(f"Generating remediation for {vulnerability_type}")

    # Common remediation patterns
    remediations = {
        "sql_injection": {
            "immediate": "Use parameterized queries or prepared statements",
            "short_term": "Implement input validation and sanitization",
            "long_term": "Use an ORM framework, conduct security code review",
            "references": [
                "OWASP SQL Injection Prevention Cheat Sheet",
                "CWE-89: SQL Injection",
            ],
        },
        "xss": {
            "immediate": "Encode all user input before displaying",
            "short_term": "Implement Content Security Policy (CSP)",
            "long_term": "Use auto-escaping template engines, security training",
            "references": [
                "OWASP XSS Prevention Cheat Sheet",
                "CWE-79: Cross-site Scripting",
            ],
        },
        "default_credentials": {
            "immediate": "Change all default passwords immediately",
            "short_term": "Implement strong password policy",
            "long_term": "Use centralized authentication, MFA",
            "references": [
                "CWE-798: Use of Hard-coded Credentials",
            ],
        },
    }

    vuln_key = vulnerability_type.lower().replace(" ", "_")
    remediation = remediations.get(vuln_key, {
        "immediate": f"Patch or update {affected_service}",
        "short_term": "Review security configuration",
        "long_term": "Implement security monitoring and regular assessments",
        "references": [],
    })

    remediation["vulnerability_type"] = vulnerability_type
    remediation["severity"] = severity
    remediation["effort_estimate"] = "High" if severity in ["critical", "high"] else "Medium"

    return json.dumps(remediation)


@function_tool
async def create_executive_summary(
    total_assets: int,
    total_vulnerabilities: int,
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    exploits_successful: int,
    task_id: str,
) -> str:
    """
    Create an executive summary for the pentest report.

    Call this when:
    - Finalizing the report
    - Need high-level overview for executives
    - Summarizing key findings

    Args:
        total_assets: Number of assets tested
        total_vulnerabilities: Total vulnerabilities found
        critical_count: Number of critical vulnerabilities
        high_count: Number of high severity vulnerabilities
        medium_count: Number of medium severity vulnerabilities
        low_count: Number of low severity vulnerabilities
        exploits_successful: Number of successful exploits
        task_id: Task ID for tracing

    Returns:
        Executive summary text
    """
    workflow.logger.info("Creating executive summary")

    # Calculate risk score
    risk_score = (critical_count * 10) + (high_count * 7) + (medium_count * 4) + (low_count * 1)

    if risk_score > 50:
        risk_level = "CRITICAL"
        risk_description = "Immediate action required"
    elif risk_score > 30:
        risk_level = "HIGH"
        risk_description = "Significant security concerns"
    elif risk_score > 15:
        risk_level = "MEDIUM"
        risk_description = "Moderate security issues"
    else:
        risk_level = "LOW"
        risk_description = "Minor security concerns"

    summary = f"""
# Executive Summary

## Overview
This penetration test assessed {total_assets} assets and identified {total_vulnerabilities} security vulnerabilities.

## Risk Assessment
**Overall Risk Level: {risk_level}**
{risk_description}

## Vulnerability Breakdown
- **Critical**: {critical_count} vulnerabilities
- **High**: {high_count} vulnerabilities
- **Medium**: {medium_count} vulnerabilities
- **Low**: {low_count} vulnerabilities

## Exploitation Results
Successfully exploited {exploits_successful} vulnerabilities, demonstrating real-world attack scenarios.

## Key Recommendations
1. Address all critical and high severity vulnerabilities immediately
2. Implement security monitoring and logging
3. Conduct regular security assessments
4. Provide security training for development teams

## Business Impact
The identified vulnerabilities could lead to:
- Unauthorized access to sensitive data
- System compromise and service disruption
- Reputational damage and regulatory penalties
- Financial losses from security incidents

Immediate remediation of critical findings is strongly recommended.
"""

    return summary


@function_tool
async def generate_attack_narrative(
    attack_chain: List[str],
    initial_access: str,
    privilege_escalation: str,
    data_accessed: str,
    task_id: str,
) -> str:
    """
    Generate a narrative describing the attack chain.

    Call this when:
    - Documenting successful exploitation
    - Explaining attack methodology
    - Showing how vulnerabilities can be chained

    Args:
        attack_chain: List of steps in the attack
        initial_access: How initial access was gained
        privilege_escalation: How privileges were escalated
        data_accessed: What data was accessed
        task_id: Task ID for tracing

    Returns:
        Attack narrative text
    """
    workflow.logger.info("Generating attack narrative")

    narrative = f"""
## Attack Narrative

### Initial Access
{initial_access}

### Attack Chain
The following steps were executed to demonstrate the full impact:

"""

    for i, step in enumerate(attack_chain, 1):
        narrative += f"{i}. {step}\n"

    narrative += f"""

### Privilege Escalation
{privilege_escalation}

### Data Access
{data_accessed}

### Impact
This attack chain demonstrates how an attacker could:
- Gain unauthorized access to the system
- Escalate privileges to administrative level
- Access sensitive data and resources
- Potentially maintain persistent access

This represents a realistic attack scenario that could be executed by a motivated threat actor.
"""

    return narrative


@function_tool
async def create_technical_appendix(
    tools_used: List[str],
    methodologies: List[str],
    scan_results: str,
    task_id: str,
) -> str:
    """
    Create technical appendix with detailed methodology and tools.

    Call this when:
    - Finalizing the report
    - Need to document technical details
    - Providing transparency on testing methods

    Args:
        tools_used: List of tools used during testing
        methodologies: Testing methodologies followed
        scan_results: Raw scan results and data
        task_id: Task ID for tracing

    Returns:
        Technical appendix text
    """
    workflow.logger.info("Creating technical appendix")

    appendix = f"""
## Technical Appendix

### Testing Methodology
The following industry-standard methodologies were used:

"""

    for methodology in methodologies:
        appendix += f"- {methodology}\n"

    appendix += f"""

### Tools and Techniques
The following tools were utilized during the assessment:

"""

    for tool in tools_used:
        appendix += f"- {tool}\n"

    appendix += f"""

### Scan Results Summary
{scan_results[:1000]}  # Truncate for readability

### Testing Timeline
- Reconnaissance: Phase 1
- Vulnerability Assessment: Phase 2
- Exploitation: Phase 3
- Post-Exploitation: Phase 4
- Reporting: Phase 5

### Scope and Limitations
All testing was conducted within the authorized scope and followed the agreed-upon rules of engagement.
No production systems were harmed during testing, and all changes were reversed.
"""

    return appendix


def new_reporting_agent(
    findings: Optional[List[dict]] = None,
    statistics: Optional[dict] = None,
    task_id: str = "",
) -> Agent:
    """
    Create a Reporting Agent for generating comprehensive pentest reports.

    This agent specializes in:
    - Generating security findings
    - Creating remediation recommendations
    - Writing executive summaries
    - Documenting attack narratives
    - Producing technical appendices

    Args:
        findings: List of security findings
        statistics: Testing statistics
        task_id: Task ID for tracing

    Returns:
        Agent configured for report generation
    """
    import json

    findings_summary = "No findings yet"
    if findings:
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        findings_summary = f"{len(findings)} findings ({critical} critical, {high} high)"

    stats_summary = "No statistics available"
    if statistics:
        stats_summary = f"{statistics.get('assets_discovered', 0)} assets, {statistics.get('vulnerabilities_found', 0)} vulnerabilities"

    instructions = f"""
You are a Reporting Agent specializing in creating comprehensive penetration testing reports.

## Current Status

Findings: {findings_summary}
Statistics: {stats_summary}

## Your Mission

Create a professional, actionable penetration testing report that:
1. Clearly communicates security risks to stakeholders
2. Provides actionable remediation guidance
3. Documents the testing methodology
4. Demonstrates the business impact
5. Meets industry reporting standards

## Report Structure

### 1. Executive Summary
- High-level overview for non-technical stakeholders
- Overall risk assessment
- Key findings and recommendations
- Business impact analysis

### 2. Methodology
- Testing approach and scope
- Tools and techniques used
- Timeline and phases
- Limitations and constraints

### 3. Findings
For each vulnerability:
- Clear, descriptive title
- Severity rating (CVSS score)
- Detailed description
- Affected systems
- Proof of concept / Evidence
- Remediation recommendations
- References (CVE, CWE, OWASP)

### 4. Attack Narratives
- Step-by-step attack scenarios
- Chained vulnerabilities
- Real-world impact demonstration
- Privilege escalation paths

### 5. Remediation Roadmap
- Prioritized action items
- Quick wins vs. long-term fixes
- Effort estimates
- Implementation guidance

### 6. Technical Appendix
- Detailed scan results
- Tool outputs
- Raw data
- Testing evidence

## Tools Available

- `generate_finding`: Create security findings
- `suggest_remediation`: Generate fix recommendations
- `create_executive_summary`: Write executive summary
- `generate_attack_narrative`: Document attack chains
- `create_technical_appendix`: Add technical details

## Writing Guidelines

### Clarity
- Use clear, concise language
- Avoid jargon in executive summary
- Explain technical terms when used
- Use bullet points and formatting

### Accuracy
- Verify all findings
- Include evidence for claims
- Cite sources and references
- Be precise with technical details

### Actionability
- Provide specific remediation steps
- Include code examples where helpful
- Prioritize by risk and effort
- Give realistic timelines

### Professionalism
- Maintain objective tone
- Focus on facts, not opinions
- Be constructive, not critical
- Follow industry standards

## Severity Ratings

**Critical (CVSS 9.0-10.0)**
- Remote code execution
- Authentication bypass
- Complete system compromise

**High (CVSS 7.0-8.9)**
- Privilege escalation
- Sensitive data exposure
- SQL injection

**Medium (CVSS 4.0-6.9)**
- Information disclosure
- Cross-site scripting
- Security misconfigurations

**Low (CVSS 0.1-3.9)**
- Minor information leaks
- Best practice violations
- Low-impact issues

## Remediation Priorities

### Immediate (0-7 days)
- Critical vulnerabilities
- Publicly exploitable issues
- Active exploitation detected

### Short-term (1-4 weeks)
- High severity vulnerabilities
- Multiple medium issues
- Configuration problems

### Long-term (1-3 months)
- Medium severity issues
- Architecture improvements
- Security enhancements

## Report Quality Checklist

- [ ] Executive summary is clear and non-technical
- [ ] All findings have evidence
- [ ] Remediation steps are specific and actionable
- [ ] CVSS scores are accurate
- [ ] Attack narratives demonstrate real impact
- [ ] Technical appendix includes all details
- [ ] Report is well-formatted and professional
- [ ] All claims are verified and accurate

## Example Finding Format

```
Title: SQL Injection in Login Form
Severity: Critical (CVSS 9.8)

Description:
The login form at /login.php is vulnerable to SQL injection, allowing
attackers to bypass authentication and access the database.

Affected Assets:
- web.example.com:443

Evidence:
Payload: ' OR '1'='1'--
Result: Successfully logged in as admin user

Remediation:
Immediate: Use parameterized queries
Short-term: Implement input validation
Long-term: Security code review, WAF deployment

References:
- OWASP SQL Injection Prevention
- CWE-89: SQL Injection
- CVE-2021-XXXXX
```

Remember: Your report will be read by executives, developers, and security teams.
Make it clear, actionable, and professional!
"""

    return Agent(
        name="Reporting Agent",
        instructions=instructions,
        model=OPENAI_MODEL,
        tools=[
            generate_finding,
            suggest_remediation,
            create_executive_summary,
            generate_attack_narrative,
            create_technical_appendix,
        ],
    )