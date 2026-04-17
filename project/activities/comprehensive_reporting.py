"""
Comprehensive Reporting System.

This module implements advanced reporting capabilities that:

1. Executive Summaries - High-level findings for leadership
2. Technical Reports - Detailed findings for security teams
3. Remediation Guidance - Actionable fix recommendations
4. Trend Analysis - Track security posture over time
5. Real-time Dashboards - Live vulnerability status

This provides actionable intelligence from continuous pentesting.
"""
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from openai import AsyncOpenAI
from temporalio import activity

from agentex.lib.utils.logging import make_logger
from agentex.lib import adk
from agentex.types.text_content import TextContent

logger = make_logger(__name__)


async def call_llm(prompt: str, system_prompt: str, temperature: float = 0.3, max_tokens: int = 3000) -> str:
    """Call LLM for report generation."""
    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    model = os.environ.get("OPENAI_MODEL", "gpt-4")

    if not api_key:
        raise ValueError("OPENAI_API_KEY not set")

    client = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=120.0,
    )

    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        temperature=temperature,
        max_tokens=max_tokens,
    )

    return response.choices[0].message.content


# =============================================================================
# REPORT TEMPLATES
# =============================================================================

EXECUTIVE_SUMMARY_TEMPLATE = """
# Executive Security Assessment Summary

**Organization:** {organization}
**Assessment Period:** {start_date} to {end_date}
**Report Generated:** {generated_date}

---

## Overall Security Posture

**Risk Level:** {risk_level}
**Security Score:** {security_score}/100

### Key Metrics

| Metric | Value |
|--------|-------|
| Critical Vulnerabilities | {critical_count} |
| High Vulnerabilities | {high_count} |
| Medium Vulnerabilities | {medium_count} |
| Low Vulnerabilities | {low_count} |
| Total Findings | {total_findings} |
| Verified Exploitable | {verified_count} |
| Zero-Day Candidates | {zero_day_count} |

---

## Top Risks

{top_risks}

---

## Recommendations

{recommendations}

---

## Trend Analysis

{trend_analysis}

---

"""

TECHNICAL_REPORT_TEMPLATE = """
# Technical Security Assessment Report

**Target:** {target}
**Assessment Type:** Continuous Automated Penetration Testing
**Report Generated:** {generated_date}

---

## Scope

{scope}

---

## Methodology

The assessment utilized the following techniques:
- Automated asset discovery and enumeration
- AI-driven vulnerability scanning
- Creative payload generation
- Behavioral anomaly detection
- Zero-day discovery through semantic reasoning
- Parallel high-speed testing
- Automated exploitation verification

---

## Findings Summary

### By Severity

| Severity | Count | Verified |
|----------|-------|----------|
| Critical | {critical_count} | {critical_verified} |
| High | {high_count} | {high_verified} |
| Medium | {medium_count} | {medium_verified} |
| Low | {low_count} | {low_verified} |

### By Type

{findings_by_type}

---

## Detailed Findings

{detailed_findings}

---

## Attack Chains

{attack_chains}

---

## Remediation Priority

{remediation_priority}

---

## Appendix

### A. Testing Tools Used
- Subfinder (Asset Discovery)
- Nmap (Port Scanning)
- Nuclei (Vulnerability Scanning)
- Httpx (HTTP Probing)
- Katana (Web Crawling)
- Custom AI Reasoning Engine

### B. Test Coverage
{test_coverage}

---

"""


# =============================================================================
# REPORTING ACTIVITIES
# =============================================================================

@activity.defn(name="generate_executive_summary_activity")
async def generate_executive_summary_activity(
    organization: str,
    findings: List[Dict[str, Any]],
    scan_history: List[Dict[str, Any]],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Generate an executive summary report.

    This activity:
    1. Analyzes findings for executive audience
    2. Calculates security metrics
    3. Identifies top risks
    4. Provides strategic recommendations
    """
    logger.info(f"Generating executive summary for {organization}")

    activity.heartbeat("Generating executive summary")

    # Calculate metrics
    severity_counts = defaultdict(int)
    verified_count = 0
    zero_day_count = 0

    for finding in findings:
        severity = finding.get("severity", "medium").lower()
        severity_counts[severity] += 1

        if finding.get("verification", {}).get("verified"):
            verified_count += 1

        if finding.get("type") == "zero_day_candidate":
            zero_day_count += 1

    total_findings = len(findings)

    # Calculate security score (inverse of risk)
    critical_weight = severity_counts.get("critical", 0) * 25
    high_weight = severity_counts.get("high", 0) * 15
    medium_weight = severity_counts.get("medium", 0) * 5
    low_weight = severity_counts.get("low", 0) * 1

    risk_score = min(100, critical_weight + high_weight + medium_weight + low_weight)
    security_score = max(0, 100 - risk_score)

    # Determine risk level
    if severity_counts.get("critical", 0) > 0 or security_score < 30:
        risk_level = "🔴 CRITICAL"
    elif severity_counts.get("high", 0) > 3 or security_score < 50:
        risk_level = "🟠 HIGH"
    elif severity_counts.get("high", 0) > 0 or security_score < 70:
        risk_level = "🟡 MEDIUM"
    else:
        risk_level = "🟢 LOW"

    # Generate top risks using AI
    top_risks_prompt = f"""Based on these security findings, identify the top 5 risks for executive leadership:

{json.dumps(findings[:20], indent=2, default=str)}

For each risk, provide:
1. Risk title
2. Business impact
3. Likelihood of exploitation
4. Recommended action

Format as markdown bullet points."""

    try:
        top_risks = await call_llm(
            top_risks_prompt,
            "You are a security consultant presenting findings to executive leadership. Be concise and focus on business impact.",
            temperature=0.3,
        )
    except Exception:
        top_risks = "- Unable to generate risk analysis"

    # Generate recommendations
    recommendations_prompt = f"""Based on these findings, provide 5 strategic security recommendations:

Critical: {severity_counts.get('critical', 0)}
High: {severity_counts.get('high', 0)}
Medium: {severity_counts.get('medium', 0)}
Zero-Day Candidates: {zero_day_count}

Provide actionable recommendations for improving security posture."""

    try:
        recommendations = await call_llm(
            recommendations_prompt,
            "You are a security advisor providing strategic recommendations to improve organizational security.",
            temperature=0.3,
        )
    except Exception:
        recommendations = "- Unable to generate recommendations"

    # Trend analysis
    if len(scan_history) > 1:
        trend_analysis = f"""
Based on {len(scan_history)} scan cycles:
- First scan: {scan_history[0].get('total_findings', 0)} findings
- Latest scan: {scan_history[-1].get('total_findings', 0)} findings
- Trend: {'Improving' if scan_history[-1].get('total_findings', 0) < scan_history[0].get('total_findings', 0) else 'Needs attention'}
"""
    else:
        trend_analysis = "Insufficient data for trend analysis. Continue monitoring."

    # Generate report
    report = EXECUTIVE_SUMMARY_TEMPLATE.format(
        organization=organization,
        start_date=(datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d"),
        end_date=datetime.utcnow().strftime("%Y-%m-%d"),
        generated_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        risk_level=risk_level,
        security_score=security_score,
        critical_count=severity_counts.get("critical", 0),
        high_count=severity_counts.get("high", 0),
        medium_count=severity_counts.get("medium", 0),
        low_count=severity_counts.get("low", 0),
        total_findings=total_findings,
        verified_count=verified_count,
        zero_day_count=zero_day_count,
        top_risks=top_risks,
        recommendations=recommendations,
        trend_analysis=trend_analysis,
    )

    # Notify about report
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 📊 Executive Summary Generated

**Organization:** {organization}
**Risk Level:** {risk_level}
**Security Score:** {security_score}/100

**Key Findings:**
- Critical: {severity_counts.get('critical', 0)}
- High: {severity_counts.get('high', 0)}
- Verified Exploitable: {verified_count}
- Zero-Day Candidates: {zero_day_count}

Full executive summary report is ready for review.""",
            ),
            trace_id=trace_id,
        )

    return {
        "report_type": "executive_summary",
        "organization": organization,
        "risk_level": risk_level,
        "security_score": security_score,
        "metrics": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "total": total_findings,
            "verified": verified_count,
            "zero_day": zero_day_count,
        },
        "report_markdown": report,
    }


@activity.defn(name="generate_technical_report_activity")
async def generate_technical_report_activity(
    target: str,
    findings: List[Dict[str, Any]],
    technologies: List[str],
    endpoints: List[str],
    attack_chains: List[Dict[str, Any]],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Generate a detailed technical report.

    This activity:
    1. Documents all findings in detail
    2. Provides technical remediation steps
    3. Includes PoC information
    4. Prioritizes remediation efforts
    """
    logger.info(f"Generating technical report for {target}")

    activity.heartbeat("Generating technical report")

    # Calculate metrics
    severity_counts = defaultdict(int)
    verified_counts = defaultdict(int)
    type_counts = defaultdict(int)

    for finding in findings:
        severity = finding.get("severity", "medium").lower()
        severity_counts[severity] += 1

        if finding.get("verification", {}).get("verified"):
            verified_counts[severity] += 1

        ftype = finding.get("test_type") or finding.get("vulnerability_type", "unknown")
        type_counts[ftype] += 1

    # Format findings by type
    findings_by_type = "\n".join([
        f"| {ftype} | {count} |"
        for ftype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
    ])

    # Generate detailed findings
    detailed_findings = []
    for i, finding in enumerate(findings[:50], 1):  # Limit to 50 findings
        severity = finding.get("severity", "medium").upper()
        ftype = finding.get("test_type") or finding.get("vulnerability_type", "unknown")
        endpoint = finding.get("endpoint", "Unknown")
        payload = finding.get("payload", "N/A")
        verified = "✅ Verified" if finding.get("verification", {}).get("verified") else "⚠️ Unverified"

        detailed_findings.append(f"""
### Finding {i}: {ftype.upper()} - {severity}

**Status:** {verified}
**Endpoint:** `{endpoint[:100]}`
**Payload:** `{payload[:100]}`

**Evidence:**
{chr(10).join([f"- {e}" for e in finding.get('indicators', [])[:3]])}

**Remediation:**
{finding.get('remediation', 'See general remediation guidance for this vulnerability type.')}

---
""")

    # Format attack chains
    if attack_chains:
        chains_text = "\n".join([
            f"### Chain {i+1}: {chain.get('name', 'Unknown')}\n{chain.get('description', 'No description')}\n"
            for i, chain in enumerate(attack_chains[:5])
        ])
    else:
        chains_text = "No attack chains identified."

    # Generate remediation priority using AI
    remediation_prompt = f"""Based on these findings, create a prioritized remediation plan:

Findings by severity:
- Critical: {severity_counts.get('critical', 0)}
- High: {severity_counts.get('high', 0)}
- Medium: {severity_counts.get('medium', 0)}
- Low: {severity_counts.get('low', 0)}

Findings by type:
{json.dumps(dict(type_counts), indent=2)}

Provide:
1. Immediate actions (24-48 hours)
2. Short-term fixes (1-2 weeks)
3. Long-term improvements (1-3 months)

Format as markdown."""

    try:
        remediation_priority = await call_llm(
            remediation_prompt,
            "You are a security engineer creating a remediation plan. Be specific and actionable.",
            temperature=0.3,
        )
    except Exception:
        remediation_priority = "Unable to generate remediation priority."

    # Scope description
    scope = f"""
- **Target Domain:** {target}
- **Technologies Detected:** {', '.join(technologies[:10]) if technologies else 'Unknown'}
- **Endpoints Tested:** {len(endpoints)}
- **Assessment Type:** Continuous Automated Penetration Testing
"""

    # Test coverage
    test_coverage = f"""
- Endpoints discovered: {len(endpoints)}
- Vulnerability types tested: {len(type_counts)}
- Findings generated: {len(findings)}
- Verified findings: {sum(verified_counts.values())}
"""

    # Generate report
    report = TECHNICAL_REPORT_TEMPLATE.format(
        target=target,
        generated_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        scope=scope,
        critical_count=severity_counts.get("critical", 0),
        critical_verified=verified_counts.get("critical", 0),
        high_count=severity_counts.get("high", 0),
        high_verified=verified_counts.get("high", 0),
        medium_count=severity_counts.get("medium", 0),
        medium_verified=verified_counts.get("medium", 0),
        low_count=severity_counts.get("low", 0),
        low_verified=verified_counts.get("low", 0),
        findings_by_type=findings_by_type,
        detailed_findings="\n".join(detailed_findings),
        attack_chains=chains_text,
        remediation_priority=remediation_priority,
        test_coverage=test_coverage,
    )

    # Notify about report
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 📋 Technical Report Generated

**Target:** `{target}`
**Total Findings:** {len(findings)}
**Verified:** {sum(verified_counts.values())}

**By Severity:**
- Critical: {severity_counts.get('critical', 0)}
- High: {severity_counts.get('high', 0)}
- Medium: {severity_counts.get('medium', 0)}
- Low: {severity_counts.get('low', 0)}

Full technical report with remediation guidance is ready.""",
            ),
            trace_id=trace_id,
        )

    return {
        "report_type": "technical",
        "target": target,
        "metrics": {
            "severity_counts": dict(severity_counts),
            "verified_counts": dict(verified_counts),
            "type_counts": dict(type_counts),
        },
        "report_markdown": report,
    }


@activity.defn(name="generate_remediation_report_activity")
async def generate_remediation_report_activity(
    findings: List[Dict[str, Any]],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Generate a focused remediation report.

    This activity:
    1. Groups findings by remediation type
    2. Provides specific fix instructions
    3. Includes code examples
    4. Prioritizes by risk
    """
    logger.info(f"Generating remediation report for {len(findings)} findings")

    activity.heartbeat("Generating remediation report")

    # Group findings by vulnerability type
    by_type = defaultdict(list)
    for finding in findings:
        ftype = finding.get("test_type") or finding.get("vulnerability_type", "unknown")
        by_type[ftype].append(finding)

    # Generate remediation for each type
    remediation_sections = []

    for vuln_type, type_findings in by_type.items():
        remediation_prompt = f"""Generate detailed remediation guidance for {len(type_findings)} {vuln_type} vulnerabilities.

Sample findings:
{json.dumps(type_findings[:3], indent=2, default=str)}

Provide:
1. Root cause explanation
2. General fix approach
3. Specific code examples (before/after)
4. Testing verification steps
5. Prevention best practices

Format as markdown with code blocks."""

        try:
            remediation = await call_llm(
                remediation_prompt,
                "You are a security engineer providing remediation guidance. Include specific code examples.",
                temperature=0.3,
            )

            remediation_sections.append(f"""
## {vuln_type.upper()} ({len(type_findings)} findings)

{remediation}

---
""")
        except Exception as e:
            remediation_sections.append(f"""
## {vuln_type.upper()} ({len(type_findings)} findings)

Unable to generate remediation: {str(e)}

---
""")

    # Compile report
    report = f"""
# Remediation Report

**Generated:** {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
**Total Findings:** {len(findings)}
**Vulnerability Types:** {len(by_type)}

---

{"".join(remediation_sections)}

## General Security Recommendations

1. **Input Validation**: Implement strict input validation on all user inputs
2. **Output Encoding**: Encode all output based on context (HTML, JavaScript, URL, etc.)
3. **Parameterized Queries**: Use parameterized queries for all database operations
4. **Least Privilege**: Apply principle of least privilege across all systems
5. **Security Headers**: Implement security headers (CSP, X-Frame-Options, etc.)
6. **Regular Updates**: Keep all software and dependencies up to date
7. **Security Testing**: Integrate security testing into CI/CD pipeline

---
"""

    # Notify about report
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🔧 Remediation Report Generated

**Total Findings:** {len(findings)}
**Vulnerability Types:** {len(by_type)}

**Remediation Sections:**
{chr(10).join([f"- {vtype}: {len(vfindings)} findings" for vtype, vfindings in by_type.items()])}

Detailed remediation guidance with code examples is ready.""",
            ),
            trace_id=trace_id,
        )

    return {
        "report_type": "remediation",
        "findings_count": len(findings),
        "vulnerability_types": list(by_type.keys()),
        "report_markdown": report,
    }


@activity.defn(name="generate_trend_report_activity")
async def generate_trend_report_activity(
    organization: str,
    scan_history: List[Dict[str, Any]],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Generate a trend analysis report.

    This activity:
    1. Analyzes security posture over time
    2. Identifies improvement areas
    3. Tracks remediation progress
    4. Predicts future risks
    """
    logger.info(f"Generating trend report for {organization}")

    activity.heartbeat("Generating trend report")

    if len(scan_history) < 2:
        return {
            "report_type": "trend",
            "error": "Insufficient scan history for trend analysis",
            "minimum_scans_required": 2,
            "current_scans": len(scan_history),
        }

    # Calculate trends
    first_scan = scan_history[0]
    latest_scan = scan_history[-1]

    # Extract metrics over time
    timeline = []
    for scan in scan_history:
        timeline.append({
            "date": scan.get("timestamp", "Unknown"),
            "total": scan.get("total_findings", 0),
            "critical": scan.get("critical", 0),
            "high": scan.get("high", 0),
            "medium": scan.get("medium", 0),
            "low": scan.get("low", 0),
        })

    # Calculate changes
    total_change = latest_scan.get("total_findings", 0) - first_scan.get("total_findings", 0)
    critical_change = latest_scan.get("critical", 0) - first_scan.get("critical", 0)

    # Determine trend direction
    if total_change < 0:
        trend_direction = "📉 Improving"
        trend_description = f"Total findings decreased by {abs(total_change)}"
    elif total_change > 0:
        trend_direction = "📈 Worsening"
        trend_description = f"Total findings increased by {total_change}"
    else:
        trend_direction = "➡️ Stable"
        trend_description = "No change in total findings"

    # Generate trend analysis using AI
    trend_prompt = f"""Analyze this security scan history and provide insights:

Scan History:
{json.dumps(timeline, indent=2)}

Provide:
1. Overall trend assessment
2. Areas of improvement
3. Areas of concern
4. Predictions for next period
5. Recommended focus areas

Format as markdown."""

    try:
        trend_analysis = await call_llm(
            trend_prompt,
            "You are a security analyst providing trend analysis. Be data-driven and actionable.",
            temperature=0.3,
        )
    except Exception:
        trend_analysis = "Unable to generate trend analysis."

    # Generate report
    report = f"""
# Security Trend Report

**Organization:** {organization}
**Analysis Period:** {first_scan.get('timestamp', 'Unknown')} to {latest_scan.get('timestamp', 'Unknown')}
**Scans Analyzed:** {len(scan_history)}
**Generated:** {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}

---

## Overall Trend

**Direction:** {trend_direction}
**Summary:** {trend_description}

---

## Metrics Over Time

| Date | Total | Critical | High | Medium | Low |
|------|-------|----------|------|--------|-----|
{chr(10).join([f"| {t['date']} | {t['total']} | {t['critical']} | {t['high']} | {t['medium']} | {t['low']} |" for t in timeline[-10:]])}

---

## Trend Analysis

{trend_analysis}

---

## Key Changes

- **Total Findings:** {first_scan.get('total_findings', 0)} → {latest_scan.get('total_findings', 0)} ({'+' if total_change > 0 else ''}{total_change})
- **Critical:** {first_scan.get('critical', 0)} → {latest_scan.get('critical', 0)} ({'+' if critical_change > 0 else ''}{critical_change})

---

"""

    # Notify about report
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 📈 Trend Report Generated

**Organization:** {organization}
**Scans Analyzed:** {len(scan_history)}
**Trend:** {trend_direction}

**Summary:** {trend_description}

**Critical Findings Trend:** {first_scan.get('critical', 0)} → {latest_scan.get('critical', 0)}

Full trend analysis with predictions is ready.""",
            ),
            trace_id=trace_id,
        )

    return {
        "report_type": "trend",
        "organization": organization,
        "scans_analyzed": len(scan_history),
        "trend_direction": trend_direction,
        "trend_description": trend_description,
        "timeline": timeline,
        "report_markdown": report,
    }


@activity.defn(name="generate_dashboard_data_activity")
async def generate_dashboard_data_activity(
    organization: str,
    findings: List[Dict[str, Any]],
    scan_history: List[Dict[str, Any]],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Generate data for real-time dashboard.

    This activity:
    1. Calculates current metrics
    2. Prepares chart data
    3. Identifies alerts
    4. Returns dashboard-ready data
    """
    logger.info(f"Generating dashboard data for {organization}")

    activity.heartbeat("Generating dashboard data")

    # Current metrics
    severity_counts = defaultdict(int)
    type_counts = defaultdict(int)
    verified_count = 0
    zero_day_count = 0

    for finding in findings:
        severity = finding.get("severity", "medium").lower()
        severity_counts[severity] += 1

        ftype = finding.get("test_type") or finding.get("vulnerability_type", "unknown")
        type_counts[ftype] += 1

        if finding.get("verification", {}).get("verified"):
            verified_count += 1

        if finding.get("type") == "zero_day_candidate":
            zero_day_count += 1

    # Calculate security score
    critical_weight = severity_counts.get("critical", 0) * 25
    high_weight = severity_counts.get("high", 0) * 15
    medium_weight = severity_counts.get("medium", 0) * 5
    low_weight = severity_counts.get("low", 0) * 1

    risk_score = min(100, critical_weight + high_weight + medium_weight + low_weight)
    security_score = max(0, 100 - risk_score)

    # Prepare chart data
    severity_chart = [
        {"name": "Critical", "value": severity_counts.get("critical", 0), "color": "#dc3545"},
        {"name": "High", "value": severity_counts.get("high", 0), "color": "#fd7e14"},
        {"name": "Medium", "value": severity_counts.get("medium", 0), "color": "#ffc107"},
        {"name": "Low", "value": severity_counts.get("low", 0), "color": "#28a745"},
    ]

    type_chart = [
        {"name": ftype, "value": count}
        for ftype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]

    # Timeline chart
    timeline_chart = [
        {
            "date": scan.get("timestamp", "Unknown"),
            "total": scan.get("total_findings", 0),
            "critical": scan.get("critical", 0),
        }
        for scan in scan_history[-30:]  # Last 30 scans
    ]

    # Generate alerts
    alerts = []

    if severity_counts.get("critical", 0) > 0:
        alerts.append({
            "level": "critical",
            "message": f"{severity_counts['critical']} critical vulnerabilities require immediate attention",
            "timestamp": datetime.utcnow().isoformat(),
        })

    if zero_day_count > 0:
        alerts.append({
            "level": "high",
            "message": f"{zero_day_count} potential zero-day vulnerabilities discovered",
            "timestamp": datetime.utcnow().isoformat(),
        })

    if len(scan_history) >= 2:
        latest = scan_history[-1].get("total_findings", 0)
        previous = scan_history[-2].get("total_findings", 0)
        if latest > previous * 1.2:  # 20% increase
            alerts.append({
                "level": "warning",
                "message": f"Significant increase in findings: {previous} → {latest}",
                "timestamp": datetime.utcnow().isoformat(),
            })

    dashboard_data = {
        "organization": organization,
        "last_updated": datetime.utcnow().isoformat(),
        "metrics": {
            "security_score": security_score,
            "total_findings": len(findings),
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "verified": verified_count,
            "zero_day_candidates": zero_day_count,
        },
        "charts": {
            "severity": severity_chart,
            "type": type_chart,
            "timeline": timeline_chart,
        },
        "alerts": alerts,
        "recent_findings": [
            {
                "type": f.get("test_type") or f.get("vulnerability_type", "unknown"),
                "severity": f.get("severity", "medium"),
                "endpoint": f.get("endpoint", "Unknown")[:50],
                "timestamp": f.get("discovered_at", "Unknown"),
            }
            for f in findings[-10:]
        ],
    }

    # Notify about dashboard update
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 📊 Dashboard Updated

**Security Score:** {security_score}/100
**Total Findings:** {len(findings)}
**Active Alerts:** {len(alerts)}

**Current Status:**
- 🔴 Critical: {severity_counts.get('critical', 0)}
- 🟠 High: {severity_counts.get('high', 0)}
- 🟡 Medium: {severity_counts.get('medium', 0)}
- 🟢 Low: {severity_counts.get('low', 0)}

Dashboard data is ready for visualization.""",
            ),
            trace_id=trace_id,
        )

    return dashboard_data