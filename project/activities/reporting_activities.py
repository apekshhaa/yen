"""Reporting activities for Major-Project agent."""
import asyncio
import json
from datetime import datetime
from typing import Any, Dict

from temporalio import activity

from agentex.lib.utils.logging import make_logger

logger = make_logger(__name__)


# Vulnerability type descriptions for generating meaningful finding descriptions
VULNERABILITY_DESCRIPTIONS = {
    "sql_injection": "SQL Injection vulnerability allows attackers to execute arbitrary SQL commands on the database, potentially leading to data theft, modification, or deletion.",
    "sqli": "SQL Injection vulnerability allows attackers to execute arbitrary SQL commands on the database, potentially leading to data theft, modification, or deletion.",
    "xss": "Cross-Site Scripting (XSS) vulnerability allows attackers to inject malicious scripts into web pages viewed by other users, potentially stealing session cookies or credentials.",
    "cross-site_scripting": "Cross-Site Scripting (XSS) vulnerability allows attackers to inject malicious scripts into web pages viewed by other users, potentially stealing session cookies or credentials.",
    "ssrf": "Server-Side Request Forgery (SSRF) vulnerability allows attackers to make requests from the server to internal resources, potentially accessing sensitive internal services.",
    "path_traversal": "Path Traversal vulnerability allows attackers to access files outside the intended directory, potentially reading sensitive configuration files or source code.",
    "lfi": "Local File Inclusion vulnerability allows attackers to include local files on the server, potentially leading to code execution or sensitive data exposure.",
    "rfi": "Remote File Inclusion vulnerability allows attackers to include remote files, potentially leading to remote code execution.",
    "command_injection": "Command Injection vulnerability allows attackers to execute arbitrary system commands on the server, potentially leading to full system compromise.",
    "rce": "Remote Code Execution vulnerability allows attackers to execute arbitrary code on the server, leading to full system compromise.",
    "xxe": "XML External Entity (XXE) vulnerability allows attackers to read local files, perform SSRF attacks, or cause denial of service.",
    "idor": "Insecure Direct Object Reference (IDOR) vulnerability allows attackers to access resources belonging to other users by manipulating object references.",
    "authentication_bypass": "Authentication Bypass vulnerability allows attackers to access protected resources without proper authentication.",
    "broken_authentication": "Broken Authentication vulnerability allows attackers to compromise user accounts or session management.",
    "sensitive_data_exposure": "Sensitive Data Exposure vulnerability reveals confidential information such as credentials, API keys, or personal data.",
    "security_misconfiguration": "Security Misconfiguration vulnerability exposes the application to attacks due to insecure default settings or incomplete configuration.",
    "default": "Security vulnerability that could allow unauthorized access or data exposure. Review the evidence and affected assets for more details.",
}

VULNERABILITY_REMEDIATIONS = {
    "sql_injection": "Use parameterized queries or prepared statements. Implement input validation and sanitization. Apply the principle of least privilege for database accounts.",
    "sqli": "Use parameterized queries or prepared statements. Implement input validation and sanitization. Apply the principle of least privilege for database accounts.",
    "xss": "Implement proper output encoding based on context (HTML, JavaScript, URL, CSS). Use Content Security Policy (CSP) headers. Validate and sanitize all user input.",
    "cross-site_scripting": "Implement proper output encoding based on context (HTML, JavaScript, URL, CSS). Use Content Security Policy (CSP) headers. Validate and sanitize all user input.",
    "ssrf": "Implement allowlists for permitted URLs and IP ranges. Disable unnecessary URL schemes. Use network segmentation to limit internal access.",
    "path_traversal": "Validate and sanitize file paths. Use allowlists for permitted files. Implement proper access controls and chroot jails.",
    "lfi": "Avoid including files based on user input. Use allowlists for permitted files. Implement proper input validation.",
    "command_injection": "Avoid executing system commands with user input. Use parameterized APIs. Implement strict input validation and sanitization.",
    "rce": "Apply security patches immediately. Implement input validation. Use sandboxing and least privilege principles.",
    "xxe": "Disable external entity processing in XML parsers. Use less complex data formats like JSON. Implement input validation.",
    "idor": "Implement proper access control checks. Use indirect object references. Validate user permissions for each request.",
    "default": "Review the vulnerability details and implement appropriate security controls. Consult security best practices for the specific vulnerability type.",
}


@activity.defn(name="generate_finding_activity")
async def generate_finding_activity(
    vulnerability: Dict[str, Any], task_id: str, trace_id: str
) -> Dict[str, Any]:
    """
    Generate a security finding from a vulnerability.

    Args:
        vulnerability: Vulnerability data
        task_id: Task ID for tracing
        trace_id: Trace ID for logging

    Returns:
        Dictionary with finding details
    """
    logger.info(f"Generating finding for vulnerability: {vulnerability.get('id')}")

    try:
        vuln_name = vulnerability.get("name", "Unknown Vulnerability")
        vuln_name_lower = vuln_name.lower().replace(" ", "_")

        # Get or generate description
        description = vulnerability.get("description", "")
        if not description or len(description) < 20:
            # Try to find a matching description
            for key, desc in VULNERABILITY_DESCRIPTIONS.items():
                if key in vuln_name_lower:
                    description = desc
                    break
            else:
                description = VULNERABILITY_DESCRIPTIONS["default"]

            # Add context about the affected asset
            affected_host = vulnerability.get("affected_host", "")
            if affected_host:
                description = f"{description} This vulnerability was found on {affected_host}."

        # Get or generate remediation
        remediation = vulnerability.get("remediation", "")
        if not remediation or len(remediation) < 20:
            for key, rem in VULNERABILITY_REMEDIATIONS.items():
                if key in vuln_name_lower:
                    remediation = rem
                    break
            else:
                remediation = VULNERABILITY_REMEDIATIONS["default"]

        finding = {
            "id": f"finding_{vulnerability.get('id')}",
            "title": vuln_name,
            "severity": vulnerability.get("severity", "info"),
            "cvss_score": vulnerability.get("cvss_score"),
            "description": description,
            "affected_assets": [vulnerability.get("affected_host", "")] if vulnerability.get("affected_host") else [],
            "evidence": vulnerability.get("evidence", ""),
            "remediation": remediation,
            "verified": vulnerability.get("verified", False),
        }

        logger.info(f"Finding generated: {finding['id']}")
        return finding

    except Exception as e:
        logger.error(f"Finding generation failed: {e}")
        return {
            "error": str(e),
        }


@activity.defn(name="generate_report_activity")
async def generate_report_activity(
    findings: list, stats: Dict[str, Any], task_id: str, trace_id: str
) -> Dict[str, Any]:
    """
    Generate comprehensive security report.

    Args:
        findings: List of security findings
        stats: Statistics from the assessment
        task_id: Task ID for tracing
        trace_id: Trace ID for logging

    Returns:
        Dictionary with report details
    """
    logger.info(f"Generating security report with {len(findings)} findings")

    try:
        await asyncio.sleep(2)

        # Count findings by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:
            severity = finding.get("severity", "info")
            if severity in severity_counts:
                severity_counts[severity] += 1

        report = {
            "id": f"report_{task_id}",
            "title": "Security Assessment Report",
            "generated_at": datetime.utcnow().isoformat(),
            "findings_summary": {
                "total_findings": len(findings),
                **severity_counts,
            },
            "findings": findings,
            "stats": stats,
        }

        logger.info(f"Report generated: {report['id']}")
        return report

    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return {
            "error": str(e),
        }


@activity.defn(name="send_notification_activity")
async def send_notification_activity(
    notification_type: str, data: Dict[str, Any], task_id: str, trace_id: str
) -> Dict[str, Any]:
    """
    Send notification (email, Slack, etc.).

    Args:
        notification_type: Type of notification (email, slack, etc.)
        data: Notification data
        task_id: Task ID for tracing
        trace_id: Trace ID for logging

    Returns:
        Dictionary with notification status
    """
    logger.info(f"Sending {notification_type} notification")

    try:
        # In production, this would send actual notifications
        await asyncio.sleep(1)

        result = {
            "notification_type": notification_type,
            "sent": True,
            "timestamp": datetime.utcnow().isoformat(),
        }

        logger.info(f"Notification sent: {notification_type}")
        return result

    except Exception as e:
        logger.error(f"Notification failed: {e}")
        return {
            "notification_type": notification_type,
            "sent": False,
            "error": str(e),
        }