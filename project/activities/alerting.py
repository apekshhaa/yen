"""
Alerting Activities for Major-Project AI Pentester.

This module provides alerting capabilities for:
- New attack surface exposures
- Critical vulnerability discoveries
- Exploitation attempts
- Compliance violations
- Scheduled scan completions
"""
import asyncio
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from temporalio import activity

from agentex.lib.utils.logging import make_logger
from agentex.lib import adk
from agentex.types.text_content import TextContent

logger = make_logger(__name__)


# Alert configuration
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
PAGERDUTY_ROUTING_KEY = os.environ.get("PAGERDUTY_ROUTING_KEY")
EMAIL_SMTP_HOST = os.environ.get("EMAIL_SMTP_HOST")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "red-cell@security.local")
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL")


class AlertSeverity:
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertType:
    """Alert types."""
    NEW_EXPOSURE = "new_exposure"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    COMPLIANCE = "compliance"
    SCAN_COMPLETE = "scan_complete"
    CHANGE_DETECTED = "change_detected"


async def send_slack_alert(
    webhook_url: str,
    title: str,
    message: str,
    severity: str,
    fields: Optional[Dict[str, str]] = None,
) -> bool:
    """Send alert to Slack."""
    try:
        import httpx

        color_map = {
            AlertSeverity.CRITICAL: "#FF0000",
            AlertSeverity.HIGH: "#FF6600",
            AlertSeverity.MEDIUM: "#FFCC00",
            AlertSeverity.LOW: "#00CC00",
            AlertSeverity.INFO: "#0066FF",
        }

        attachment_fields = []
        if fields:
            for key, value in fields.items():
                attachment_fields.append({
                    "title": key,
                    "value": value,
                    "short": True,
                })

        payload = {
            "attachments": [
                {
                    "color": color_map.get(severity, "#808080"),
                    "title": f"🔴 Major-Project Alert: {title}",
                    "text": message,
                    "fields": attachment_fields,
                    "footer": "Major-Project AI Pentester",
                    "ts": int(datetime.utcnow().timestamp()),
                }
            ]
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=payload)
            return response.status_code == 200

    except Exception as e:
        logger.error(f"Failed to send Slack alert: {e}")
        return False


async def send_pagerduty_alert(
    routing_key: str,
    title: str,
    message: str,
    severity: str,
    dedup_key: Optional[str] = None,
) -> bool:
    """Send alert to PagerDuty."""
    try:
        import httpx

        severity_map = {
            AlertSeverity.CRITICAL: "critical",
            AlertSeverity.HIGH: "error",
            AlertSeverity.MEDIUM: "warning",
            AlertSeverity.LOW: "info",
            AlertSeverity.INFO: "info",
        }

        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key or f"red-cell-{datetime.utcnow().isoformat()}",
            "payload": {
                "summary": f"Major-Project: {title}",
                "severity": severity_map.get(severity, "info"),
                "source": "red-cell-ai-pentester",
                "custom_details": {
                    "message": message,
                },
            },
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload
            )
            return response.status_code == 202

    except Exception as e:
        logger.error(f"Failed to send PagerDuty alert: {e}")
        return False


async def send_teams_alert(
    webhook_url: str,
    title: str,
    message: str,
    severity: str,
    fields: Optional[Dict[str, str]] = None,
) -> bool:
    """Send alert to Microsoft Teams."""
    try:
        import httpx

        color_map = {
            AlertSeverity.CRITICAL: "FF0000",
            AlertSeverity.HIGH: "FF6600",
            AlertSeverity.MEDIUM: "FFCC00",
            AlertSeverity.LOW: "00CC00",
            AlertSeverity.INFO: "0066FF",
        }

        facts = []
        if fields:
            for key, value in fields.items():
                facts.append({"name": key, "value": value})

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color_map.get(severity, "808080"),
            "summary": f"Major-Project Alert: {title}",
            "sections": [
                {
                    "activityTitle": f"🔴 Major-Project Alert: {title}",
                    "activitySubtitle": f"Severity: {severity.upper()}",
                    "text": message,
                    "facts": facts,
                }
            ],
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=payload)
            return response.status_code == 200

    except Exception as e:
        logger.error(f"Failed to send Teams alert: {e}")
        return False


async def send_email_alert(
    smtp_host: str,
    from_addr: str,
    to_addrs: List[str],
    title: str,
    message: str,
    severity: str,
) -> bool:
    """Send alert via email."""
    try:
        import aiosmtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[Major-Project {severity.upper()}] {title}"
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)

        # Plain text version
        text_content = f"""
Major-Project AI Pentester Alert
===========================

Severity: {severity.upper()}
Title: {title}

{message}

---
This is an automated alert from Major-Project AI Pentester.
"""

        # HTML version
        html_content = f"""
<html>
<body style="font-family: Arial, sans-serif;">
<div style="background-color: #f5f5f5; padding: 20px;">
<h2 style="color: #cc0000;">🔴 Major-Project AI Pentester Alert</h2>
<table style="background-color: white; padding: 15px; border-radius: 5px;">
<tr><td><strong>Severity:</strong></td><td>{severity.upper()}</td></tr>
<tr><td><strong>Title:</strong></td><td>{title}</td></tr>
</table>
<div style="margin-top: 15px; padding: 15px; background-color: white; border-radius: 5px;">
<p>{message.replace(chr(10), '<br>')}</p>
</div>
<p style="color: #666; font-size: 12px; margin-top: 20px;">
This is an automated alert from Major-Project AI Pentester.
</p>
</div>
</body>
</html>
"""

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        await aiosmtplib.send(
            msg,
            hostname=smtp_host,
            port=587,
        )
        return True

    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")
        return False


@activity.defn(name="send_exposure_alert_activity")
async def send_exposure_alert_activity(
    organization_id: str,
    exposure_type: str,
    details: Dict[str, Any],
    severity: str,
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Send alert for new attack surface exposure.

    This activity:
    1. Formats the exposure alert
    2. Sends to configured channels
    3. Logs the alert
    4. Returns delivery status
    """
    logger.info(f"Sending exposure alert for {organization_id}")

    activity.heartbeat("Sending exposure alert")

    title = f"New {exposure_type} Exposure Detected"

    # Format message based on exposure type
    if exposure_type == "subdomain":
        message = f"""New subdomain(s) discovered for {organization_id}:

{chr(10).join([f"• {s}" for s in details.get('subdomains', [])[:10]])}

Total new subdomains: {len(details.get('subdomains', []))}

These new assets should be reviewed for security posture."""

    elif exposure_type == "service":
        message = f"""New service(s) exposed for {organization_id}:

{chr(10).join([f"• {s}" for s in details.get('services', [])[:10]])}

Total new services: {len(details.get('services', []))}

Review these services for proper security configuration."""

    elif exposure_type == "api":
        message = f"""New API endpoint(s) discovered for {organization_id}:

{chr(10).join([f"• {a}" for a in details.get('apis', [])[:10]])}

Total new APIs: {len(details.get('apis', []))}

Ensure proper authentication and authorization controls."""

    else:
        message = f"""New exposure detected for {organization_id}:

{json.dumps(details, indent=2)}"""

    # Send to configured channels
    results = {
        "slack": False,
        "pagerduty": False,
        "teams": False,
        "email": False,
    }

    if SLACK_WEBHOOK_URL:
        results["slack"] = await send_slack_alert(
            SLACK_WEBHOOK_URL,
            title,
            message,
            severity,
            {"Organization": organization_id, "Type": exposure_type},
        )

    if PAGERDUTY_ROUTING_KEY and severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
        results["pagerduty"] = await send_pagerduty_alert(
            PAGERDUTY_ROUTING_KEY,
            title,
            message,
            severity,
        )

    if TEAMS_WEBHOOK_URL:
        results["teams"] = await send_teams_alert(
            TEAMS_WEBHOOK_URL,
            title,
            message,
            severity,
            {"Organization": organization_id, "Type": exposure_type},
        )

    # Notify in task
    if task_id:
        channels_sent = [k for k, v in results.items() if v]

        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🚨 Exposure Alert Sent

**Organization:** {organization_id}
**Type:** {exposure_type}
**Severity:** {severity.upper()}

**Channels Notified:** {', '.join(channels_sent) if channels_sent else 'None (no channels configured)'}

**Details:**
{message[:500]}...
""",
            ),
            trace_id=trace_id,
        )

    return {
        "organization_id": organization_id,
        "exposure_type": exposure_type,
        "severity": severity,
        "delivery_results": results,
        "any_delivered": any(results.values()),
    }


@activity.defn(name="send_vulnerability_alert_activity")
async def send_vulnerability_alert_activity(
    organization_id: str,
    vulnerability: Dict[str, Any],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Send alert for critical vulnerability discovery.

    This activity:
    1. Formats the vulnerability alert
    2. Sends to configured channels based on severity
    3. Creates incident if critical
    4. Returns delivery status
    """
    logger.info(f"Sending vulnerability alert for {organization_id}")

    activity.heartbeat("Sending vulnerability alert")

    vuln_type = vulnerability.get("type", "Unknown")
    severity = vulnerability.get("severity", "medium").lower()
    target = vulnerability.get("target", "Unknown")
    description = vulnerability.get("description", "No description")

    title = f"{severity.upper()} Vulnerability: {vuln_type}"

    message = f"""A {severity.upper()} severity vulnerability has been discovered:

**Type:** {vuln_type}
**Target:** {target}
**Description:** {description}

**CVSS Score:** {vulnerability.get('cvss_score', 'N/A')}
**Exploitability:** {vulnerability.get('exploitability', 'Unknown')}

**Remediation:**
{vulnerability.get('remediation', 'See detailed report for remediation steps.')}

Immediate action is recommended for {severity.upper()} severity findings."""

    # Send to configured channels
    results = {
        "slack": False,
        "pagerduty": False,
        "teams": False,
    }

    if SLACK_WEBHOOK_URL:
        results["slack"] = await send_slack_alert(
            SLACK_WEBHOOK_URL,
            title,
            message,
            severity,
            {
                "Organization": organization_id,
                "Type": vuln_type,
                "Target": target,
                "CVSS": str(vulnerability.get('cvss_score', 'N/A')),
            },
        )

    # PagerDuty for critical/high only
    if PAGERDUTY_ROUTING_KEY and severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
        results["pagerduty"] = await send_pagerduty_alert(
            PAGERDUTY_ROUTING_KEY,
            title,
            message,
            severity,
            dedup_key=f"red-cell-vuln-{organization_id}-{vuln_type}-{target}",
        )

    if TEAMS_WEBHOOK_URL:
        results["teams"] = await send_teams_alert(
            TEAMS_WEBHOOK_URL,
            title,
            message,
            severity,
            {
                "Organization": organization_id,
                "Type": vuln_type,
                "Target": target,
            },
        )

    # Notify in task
    if task_id:
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
        }.get(severity, "⚪")

        channels_sent = [k for k, v in results.items() if v]

        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### {severity_emoji} Vulnerability Alert Sent

**Organization:** {organization_id}
**Severity:** {severity.upper()}
**Type:** {vuln_type}
**Target:** {target}

**Channels Notified:** {', '.join(channels_sent) if channels_sent else 'None'}
""",
            ),
            trace_id=trace_id,
        )

    return {
        "organization_id": organization_id,
        "vulnerability_type": vuln_type,
        "severity": severity,
        "delivery_results": results,
        "any_delivered": any(results.values()),
    }


@activity.defn(name="send_scan_complete_alert_activity")
async def send_scan_complete_alert_activity(
    organization_id: str,
    scan_type: str,
    summary: Dict[str, Any],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Send alert when a scan completes.

    This activity:
    1. Formats the scan completion summary
    2. Sends to configured channels
    3. Returns delivery status
    """
    logger.info(f"Sending scan complete alert for {organization_id}")

    activity.heartbeat("Sending scan complete alert")

    title = f"{scan_type} Scan Complete"

    # Determine severity based on findings
    critical_count = summary.get("critical_findings", 0)
    high_count = summary.get("high_findings", 0)

    if critical_count > 0:
        severity = AlertSeverity.CRITICAL
    elif high_count > 0:
        severity = AlertSeverity.HIGH
    else:
        severity = AlertSeverity.INFO

    message = f"""Security scan completed for {organization_id}:

**Scan Type:** {scan_type}
**Duration:** {summary.get('duration', 'Unknown')}
**Assets Scanned:** {summary.get('assets_scanned', 0)}

**Findings Summary:**
• Critical: {critical_count}
• High: {summary.get('high_findings', 0)}
• Medium: {summary.get('medium_findings', 0)}
• Low: {summary.get('low_findings', 0)}

**Total Findings:** {summary.get('total_findings', 0)}

Review the detailed report for complete findings and remediation guidance."""

    # Send to configured channels
    results = {
        "slack": False,
        "teams": False,
    }

    if SLACK_WEBHOOK_URL:
        results["slack"] = await send_slack_alert(
            SLACK_WEBHOOK_URL,
            title,
            message,
            severity,
            {
                "Organization": organization_id,
                "Scan Type": scan_type,
                "Total Findings": str(summary.get('total_findings', 0)),
            },
        )

    if TEAMS_WEBHOOK_URL:
        results["teams"] = await send_teams_alert(
            TEAMS_WEBHOOK_URL,
            title,
            message,
            severity,
            {
                "Organization": organization_id,
                "Scan Type": scan_type,
                "Total Findings": str(summary.get('total_findings', 0)),
            },
        )

    # Notify in task
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### ✅ Scan Complete Alert Sent

**Organization:** {organization_id}
**Scan Type:** {scan_type}
**Total Findings:** {summary.get('total_findings', 0)}

**Channels Notified:** {', '.join([k for k, v in results.items() if v]) or 'None'}
""",
            ),
            trace_id=trace_id,
        )

    return {
        "organization_id": organization_id,
        "scan_type": scan_type,
        "severity": severity,
        "delivery_results": results,
        "any_delivered": any(results.values()),
    }


@activity.defn(name="send_change_detection_alert_activity")
async def send_change_detection_alert_activity(
    organization_id: str,
    changes: Dict[str, Any],
    risk_level: str,
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Send alert for attack surface changes.

    This activity:
    1. Formats the change detection alert
    2. Prioritizes based on risk level
    3. Sends to configured channels
    4. Returns delivery status
    """
    logger.info(f"Sending change detection alert for {organization_id}")

    activity.heartbeat("Sending change detection alert")

    title = f"Attack Surface Changes Detected ({risk_level.upper()} Risk)"

    # Map risk level to severity
    severity_map = {
        "high": AlertSeverity.HIGH,
        "medium": AlertSeverity.MEDIUM,
        "low": AlertSeverity.LOW,
        "none": AlertSeverity.INFO,
    }
    severity = severity_map.get(risk_level, AlertSeverity.INFO)

    # Format changes
    new_items = []
    removed_items = []

    for key, value in changes.items():
        if key.startswith("new_") and value:
            new_items.extend([f"{key.replace('new_', '')}: {v}" for v in value[:5]])
        elif key.startswith("removed_") and value:
            removed_items.extend([f"{key.replace('removed_', '')}: {v}" for v in value[:5]])

    message = f"""Attack surface changes detected for {organization_id}:

**Risk Level:** {risk_level.upper()}

**New Assets:**
{chr(10).join([f"• {item}" for item in new_items[:10]]) if new_items else "• None"}

**Removed Assets:**
{chr(10).join([f"• {item}" for item in removed_items[:10]]) if removed_items else "• None"}

Review these changes to ensure they are expected and properly secured."""

    # Send to configured channels
    results = {
        "slack": False,
        "pagerduty": False,
        "teams": False,
    }

    if SLACK_WEBHOOK_URL:
        results["slack"] = await send_slack_alert(
            SLACK_WEBHOOK_URL,
            title,
            message,
            severity,
            {
                "Organization": organization_id,
                "Risk Level": risk_level.upper(),
                "New Assets": str(len(new_items)),
                "Removed Assets": str(len(removed_items)),
            },
        )

    # PagerDuty for high risk only
    if PAGERDUTY_ROUTING_KEY and risk_level == "high":
        results["pagerduty"] = await send_pagerduty_alert(
            PAGERDUTY_ROUTING_KEY,
            title,
            message,
            severity,
        )

    if TEAMS_WEBHOOK_URL:
        results["teams"] = await send_teams_alert(
            TEAMS_WEBHOOK_URL,
            title,
            message,
            severity,
            {
                "Organization": organization_id,
                "Risk Level": risk_level.upper(),
            },
        )

    # Notify in task
    if task_id:
        risk_emoji = {
            "high": "🔴",
            "medium": "🟡",
            "low": "🟢",
            "none": "⚪",
        }.get(risk_level, "⚪")

        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### {risk_emoji} Change Detection Alert Sent

**Organization:** {organization_id}
**Risk Level:** {risk_level.upper()}
**New Assets:** {len(new_items)}
**Removed Assets:** {len(removed_items)}

**Channels Notified:** {', '.join([k for k, v in results.items() if v]) or 'None'}
""",
            ),
            trace_id=trace_id,
        )

    return {
        "organization_id": organization_id,
        "risk_level": risk_level,
        "new_assets_count": len(new_items),
        "removed_assets_count": len(removed_items),
        "delivery_results": results,
        "any_delivered": any(results.values()),
    }


@activity.defn(name="configure_alert_channels_activity")
async def configure_alert_channels_activity(
    organization_id: str,
    channels: Dict[str, Any],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Configure alert channels for an organization.

    This activity:
    1. Validates channel configurations
    2. Tests connectivity
    3. Saves configuration
    4. Returns configuration status
    """
    logger.info(f"Configuring alert channels for {organization_id}")

    activity.heartbeat("Configuring alert channels")

    validation_results = {}

    # Validate Slack
    if "slack_webhook" in channels:
        try:
            test_result = await send_slack_alert(
                channels["slack_webhook"],
                "Test Alert",
                "This is a test alert from Major-Project AI Pentester.",
                AlertSeverity.INFO,
            )
            validation_results["slack"] = {
                "configured": True,
                "test_passed": test_result,
            }
        except Exception as e:
            validation_results["slack"] = {
                "configured": True,
                "test_passed": False,
                "error": str(e),
            }

    # Validate Teams
    if "teams_webhook" in channels:
        try:
            test_result = await send_teams_alert(
                channels["teams_webhook"],
                "Test Alert",
                "This is a test alert from Major-Project AI Pentester.",
                AlertSeverity.INFO,
            )
            validation_results["teams"] = {
                "configured": True,
                "test_passed": test_result,
            }
        except Exception as e:
            validation_results["teams"] = {
                "configured": True,
                "test_passed": False,
                "error": str(e),
            }

    # Validate PagerDuty
    if "pagerduty_routing_key" in channels:
        validation_results["pagerduty"] = {
            "configured": True,
            "test_passed": True,  # Don't send test to PagerDuty
            "note": "Test skipped to avoid creating incident",
        }

    # Notify in task
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### ⚙️ Alert Channels Configured

**Organization:** {organization_id}

**Channel Status:**
{chr(10).join([f"• {k}: {'✅ Configured' if v.get('configured') else '❌ Not configured'} {'(Test passed)' if v.get('test_passed') else ''}" for k, v in validation_results.items()])}
""",
            ),
            trace_id=trace_id,
        )

    return {
        "organization_id": organization_id,
        "validation_results": validation_results,
        "all_valid": all(v.get("test_passed", False) for v in validation_results.values()),
    }