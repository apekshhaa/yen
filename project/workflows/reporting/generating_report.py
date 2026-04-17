"""Generating report workflow state.

Enhanced with:
- Executive summaries for leadership
- Technical reports for security teams
- Remediation guidance with code examples
- Trend analysis over time
- Real-time dashboard data
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional, override
import uuid

from temporalio import workflow
from temporalio.common import RetryPolicy

from agentex.lib import adk
from agentex.lib.sdk.state_machine import StateMachine
from agentex.lib.sdk.state_machine.state_workflow import StateWorkflow
from agentex.lib.utils.logging import make_logger
from agentex.types.text_content import TextContent
from agentex.types.tool_request_content import ToolRequestContent
from agentex.types.tool_response_content import ToolResponseContent
from project.state_machines.major_project_agent import (
    MajorProjectData,
    MajorProjectState,
    Finding,
)

logger = make_logger(__name__)

# Import activities with workflow.unsafe context
with workflow.unsafe.imports_passed_through():
    from project.activities.reporting_activities import (
        generate_finding_activity,
        generate_report_activity,
    )
    # NEW: Comprehensive reporting activities
    from project.activities.comprehensive_reporting import (
        generate_executive_summary_activity,
        generate_technical_report_activity,
        generate_remediation_report_activity,
        generate_trend_report_activity,
        generate_dashboard_data_activity,
    )
    # Attack surface history for trends
    from project.activities.attack_surface_history import (
        save_vulnerability_finding_activity as save_vuln_history_activity,
        get_vulnerability_trends_activity,
    )
    # NEW: Exploitation verification activities
    from project.activities.exploitation_verification import (
        batch_verify_findings_activity,
        measure_impact_activity,
    )
    # NEW: Pentest memory activities
    from project.activities.pentest_memory import (
        get_memory_statistics_activity,
    )
    # Alerting activities
    from project.activities.alerting import (
        send_scan_complete_alert_activity,
        send_vulnerability_alert_activity,
    )


class GeneratingReportWorkflow(StateWorkflow):
    """Workflow for generating comprehensive security report.

    Enhanced with:
    - Batch verification of findings
    - Executive summaries for leadership
    - Technical reports for security teams
    - Remediation guidance with code examples
    - Memory statistics and learning insights
    """

    @override
    async def execute(
        self,
        state_machine: StateMachine,
        state_machine_data: Optional[MajorProjectData] = None,
    ) -> str:
        """
        Generate comprehensive security assessment report.
        """
        if state_machine_data is None:
            return MajorProjectState.FAILED

        logger.info("Generating security report...")
        task_id = state_machine_data.task_id

        try:
            # Generate comprehensive report
            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=ToolRequestContent(
                        author="agent",
                        name="generate_report",
                        arguments={
                            "findings": len(state_machine_data.findings),
                            "vulnerabilities": len(state_machine_data.vulnerabilities),
                        },
                        tool_call_id=f"generate_report_{len(state_machine_data.findings)}",
                    ),
                    trace_id=task_id,
                )

            # ===== BATCH VERIFY FINDINGS =====
            # Verify all findings to eliminate false positives
            if state_machine_data.vulnerabilities:
                if task_id:
                    await adk.messages.create(
                        task_id=task_id,
                        content=TextContent(
                            author="agent",
                            content=f"**🔍 Verifying {len(state_machine_data.vulnerabilities)} findings to eliminate false positives...**",
                        ),
                        trace_id=task_id,
                    )

                try:
                    # Prepare findings for verification
                    findings_to_verify = []
                    for vuln in state_machine_data.vulnerabilities[:50]:  # Limit to 50
                        findings_to_verify.append({
                            "endpoint": vuln.affected_asset,
                            "test_type": vuln.scanner if vuln.scanner != "ai_agent" else "xss",  # Default type
                            "vulnerability_type": vuln.name.lower().replace(" ", "_"),
                            "payload": vuln.evidence[:100] if vuln.evidence else "",
                            "severity": vuln.severity,
                        })

                    verification_result = await workflow.execute_activity(
                        batch_verify_findings_activity,
                        args=[
                            findings_to_verify,
                            task_id,
                            task_id,
                        ],
                        start_to_close_timeout=timedelta(seconds=300),
                        heartbeat_timeout=timedelta(seconds=60),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )

                    # Update verification status
                    verified_count = verification_result.get("verified_count", 0)
                    logger.info(f"Verified {verified_count} out of {len(findings_to_verify)} findings")

                    # Mark verified vulnerabilities
                    verified_endpoints = set()
                    for vf in verification_result.get("verified_findings", []):
                        verified_endpoints.add(vf.get("endpoint", ""))

                    for vuln in state_machine_data.vulnerabilities:
                        if vuln.affected_asset in verified_endpoints:
                            vuln.verified = True

                except Exception as e:
                    logger.warning(f"Batch verification failed: {e}")

            # Generate findings from vulnerabilities
            for vuln in state_machine_data.vulnerabilities:
                finding_result = await workflow.execute_activity(
                    generate_finding_activity,
                    args=[
                        {
                            "id": vuln.id,
                            "name": vuln.name,
                            "severity": vuln.severity,
                            "cvss_score": vuln.cvss_score,
                            "description": vuln.description,
                            "affected_host": vuln.affected_asset,
                            "evidence": vuln.evidence,
                            "verified": vuln.verified,
                        },
                        task_id,
                        task_id,
                    ],
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )

                if "error" not in finding_result:
                    finding = Finding(
                        id=finding_result.get("id", str(uuid.uuid4())),
                        title=finding_result.get("title", ""),
                        severity=finding_result.get("severity", "info"),
                        cvss_score=finding_result.get("cvss_score"),
                        description=finding_result.get("description", ""),
                        affected_assets=finding_result.get("affected_assets", []),
                        evidence=finding_result.get("evidence", ""),
                        remediation=finding_result.get("remediation", ""),
                        verified=finding_result.get("verified", False),
                    )
                    state_machine_data.findings.append(finding)

            # ===== GENERATE EXECUTIVE SUMMARY =====
            # Generate AI-powered executive summary
            try:
                organization = state_machine_data.target_scope.domains[0] if state_machine_data.target_scope else "Unknown"

                exec_summary_result = await workflow.execute_activity(
                    generate_executive_summary_activity,
                    args=[
                        organization,
                        [f.dict() for f in state_machine_data.findings],
                        [state_machine_data.stats],  # Scan history
                        task_id,
                        task_id,
                    ],
                    start_to_close_timeout=timedelta(seconds=120),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )

                state_machine_data.executive_summary = exec_summary_result.get("report_markdown", "")
                state_machine_data.result["executive_summary"] = exec_summary_result

            except Exception as e:
                logger.warning(f"Executive summary generation failed: {e}")
                # Fallback to basic summary
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                for finding in state_machine_data.findings:
                    if finding.severity in severity_counts:
                        severity_counts[finding.severity] += 1

                state_machine_data.executive_summary = f"""
# Security Assessment Summary

**Assessment Date:** {datetime.utcnow().strftime('%Y-%m-%d')}
**Total Findings:** {len(state_machine_data.findings)}

## Severity Breakdown
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Info: {severity_counts['info']}

## Assets Tested
- Total Assets: {len(state_machine_data.discovered_assets)}
- Ports Scanned: {state_machine_data.stats.get('ports_scanned', 0)}
- Services Identified: {state_machine_data.stats.get('services_identified', 0)}
"""

            # ===== GENERATE TECHNICAL REPORT =====
            # Generate detailed technical report
            try:
                target = state_machine_data.target_scope.domains[0] if state_machine_data.target_scope else "Unknown"
                technologies = list(set(
                    tech for asset in state_machine_data.discovered_assets
                    for tech in asset.technologies
                ))
                endpoints = [asset.hostname for asset in state_machine_data.discovered_assets if asset.hostname]
                attack_chains = getattr(state_machine_data, "attack_chains", [])

                tech_report_result = await workflow.execute_activity(
                    generate_technical_report_activity,
                    args=[
                        target,
                        [f.dict() for f in state_machine_data.findings],
                        technologies,
                        endpoints,
                        attack_chains,
                        task_id,
                        task_id,
                    ],
                    start_to_close_timeout=timedelta(seconds=180),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )

                state_machine_data.result["technical_report"] = tech_report_result

            except Exception as e:
                logger.warning(f"Technical report generation failed: {e}")

            # ===== GENERATE REMEDIATION REPORT =====
            # Generate remediation guidance
            try:
                remediation_result = await workflow.execute_activity(
                    generate_remediation_report_activity,
                    args=[
                        [f.dict() for f in state_machine_data.findings],
                        task_id,
                        task_id,
                    ],
                    start_to_close_timeout=timedelta(seconds=180),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )

                state_machine_data.result["remediation_report"] = remediation_result

            except Exception as e:
                logger.warning(f"Remediation report generation failed: {e}")

            # ===== GENERATE TREND REPORT =====
            # Generate trend analysis over time
            try:
                organization = state_machine_data.target_scope.domains[0] if state_machine_data.target_scope else "Unknown"

                # Get vulnerability trends
                trends_data = await workflow.execute_activity(
                    get_vulnerability_trends_activity,
                    args=[organization, 30, task_id, task_id],  # Last 30 days
                    start_to_close_timeout=timedelta(seconds=60),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )

                # Generate trend report
                trend_report_result = await workflow.execute_activity(
                    generate_trend_report_activity,
                    args=[
                        organization,
                        trends_data.get("trends", []),
                        30,  # days
                        task_id,
                        task_id,
                    ],
                    start_to_close_timeout=timedelta(seconds=120),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )

                state_machine_data.result["trend_report"] = trend_report_result

            except Exception as e:
                logger.warning(f"Trend report generation failed: {e}")

            # ===== GENERATE DASHBOARD DATA =====
            # Generate real-time dashboard data
            try:
                organization = state_machine_data.target_scope.domains[0] if state_machine_data.target_scope else "Unknown"

                dashboard_result = await workflow.execute_activity(
                    generate_dashboard_data_activity,
                    args=[
                        organization,
                        [f.dict() for f in state_machine_data.findings],
                        [
                            {
                                "hostname": a.hostname,
                                "ip_address": a.ip_address,
                                "ports": a.ports,
                                "technologies": a.technologies,
                                "risk_score": getattr(a, "risk_score", 0),
                            }
                            for a in state_machine_data.discovered_assets
                        ],
                        task_id,
                        task_id,
                    ],
                    start_to_close_timeout=timedelta(seconds=60),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )

                state_machine_data.result["dashboard_data"] = dashboard_result

            except Exception as e:
                logger.warning(f"Dashboard data generation failed: {e}")

            # ===== SAVE VULNERABILITY FINDINGS TO HISTORY =====
            # Save findings for historical tracking
            try:
                organization = state_machine_data.target_scope.domains[0] if state_machine_data.target_scope else "Unknown"

                for finding in state_machine_data.findings[:50]:  # Limit to 50
                    await workflow.execute_activity(
                        save_vuln_history_activity,
                        args=[
                            organization,
                            {
                                "id": finding.id,
                                "title": finding.title,
                                "severity": finding.severity,
                                "cvss_score": finding.cvss_score,
                                "affected_assets": finding.affected_assets,
                                "verified": finding.verified,
                            },
                            task_id,
                            task_id,
                        ],
                        start_to_close_timeout=timedelta(seconds=30),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )

                logger.info(f"Saved {len(state_machine_data.findings)} findings to history")

            except Exception as e:
                logger.warning(f"Failed to save vulnerability history: {e}")

            # ===== GET MEMORY STATISTICS =====
            # Show learning progress
            try:
                memory_stats = await workflow.execute_activity(
                    get_memory_statistics_activity,
                    args=[
                        task_id,
                        task_id,
                    ],
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )

                state_machine_data.result["memory_statistics"] = memory_stats

            except Exception as e:
                logger.warning(f"Memory statistics retrieval failed: {e}")

            # Generate basic report as well
            report_result = await workflow.execute_activity(
                generate_report_activity,
                args=[
                    [f.dict() for f in state_machine_data.findings],
                    state_machine_data.stats,
                    task_id,
                    task_id,
                ],
                start_to_close_timeout=timedelta(seconds=60),
                retry_policy=RetryPolicy(maximum_attempts=2),
            )

            if "error" not in report_result:
                state_machine_data.report_id = report_result.get("id")
                state_machine_data.report_generated = True
                state_machine_data.result["basic_report"] = report_result

            # Count findings by severity
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            verified_count = 0
            for finding in state_machine_data.findings:
                if finding.severity in severity_counts:
                    severity_counts[finding.severity] += 1
                if finding.verified:
                    verified_count += 1

            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=ToolResponseContent(
                        author="agent",
                        tool_call_id=f"generate_report_{len(state_machine_data.findings)}",
                        name="generate_report",
                        content=f"Report generated with ID: {state_machine_data.report_id}",
                    ),
                    trace_id=task_id,
                )

                # Send the comprehensive report
                zero_day_count = state_machine_data.stats.get("zero_day_candidates", 0)
                attack_chain_count = state_machine_data.stats.get("attack_chains_found", 0)

                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"""{state_machine_data.executive_summary}

## 📊 Assessment Statistics

| Metric | Value |
|--------|-------|
| Total Findings | {len(state_machine_data.findings)} |
| Verified Findings | {verified_count} |
| Zero-Day Candidates | {zero_day_count} |
| Attack Chains | {attack_chain_count} |
| Assets Tested | {len(state_machine_data.discovered_assets)} |

## 🔴 Findings by Severity

- 🔴 Critical: {severity_counts['critical']}
- 🟠 High: {severity_counts['high']}
- 🟡 Medium: {severity_counts['medium']}
- 🟢 Low: {severity_counts['low']}
- ⚪ Info: {severity_counts['info']}

## 📋 All Findings

{chr(10).join([
    f"### {i+1}. {f.title} ({f.severity.upper()}) {'✅ Verified' if f.verified else ''}\n"
    f"**Affected:** {', '.join(f.affected_assets[:3]) if f.affected_assets else 'N/A'}\n"
    f"{f.description if f.description else 'No description available.'}\n"
    f"**Remediation:** {f.remediation[:150] + '...' if f.remediation and len(f.remediation) > 150 else (f.remediation or 'See technical report for details.')}"
    for i, f in enumerate(state_machine_data.findings)
])}

---

## 📁 Reports Generated

- ✅ Executive Summary
- ✅ Technical Report
- ✅ Remediation Guidance

**Report ID:** {state_machine_data.report_id}

Assessment complete. Ready for human review.""",
                    ),
                    trace_id=task_id,
                )

            # ===== SEND SCAN COMPLETE ALERT =====
            # Send notification to configured channels (Slack, Teams, etc.)
            try:
                organization = state_machine_data.target_scope.domains[0] if state_machine_data.target_scope else "Unknown"

                await workflow.execute_activity(
                    send_scan_complete_alert_activity,
                    args=[
                        organization,
                        "Security Assessment",
                        {
                            "duration": f"{state_machine_data.stats.get('duration_seconds', 0):.0f} seconds",
                            "assets_scanned": len(state_machine_data.discovered_assets),
                            "total_findings": len(state_machine_data.findings),
                            "critical_findings": severity_counts["critical"],
                            "high_findings": severity_counts["high"],
                            "medium_findings": severity_counts["medium"],
                            "low_findings": severity_counts["low"],
                        },
                        task_id,
                        task_id,
                    ],
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )
                logger.info("Scan complete alert sent successfully")
            except Exception as e:
                logger.warning(f"Failed to send scan complete alert: {e}")

            # Send alerts for critical vulnerabilities
            try:
                critical_vulns = [v for v in state_machine_data.vulnerabilities if v.severity == "critical"]
                for vuln in critical_vulns[:5]:  # Limit to 5 critical alerts
                    await workflow.execute_activity(
                        send_vulnerability_alert_activity,
                        args=[
                            organization,
                            {
                                "type": vuln.name,
                                "severity": vuln.severity,
                                "target": vuln.affected_asset,
                                "description": vuln.description or "Critical vulnerability detected",
                                "cvss_score": vuln.cvss_score,
                                "exploitability": "High" if vuln.verified else "Unknown",
                                "remediation": vuln.remediation or "See technical report for details",
                            },
                            task_id,
                            task_id,
                        ],
                        start_to_close_timeout=timedelta(seconds=30),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                logger.info(f"Sent {len(critical_vulns[:5])} critical vulnerability alerts")
            except Exception as e:
                logger.warning(f"Failed to send vulnerability alerts: {e}")

            logger.info(f"Report generated: {state_machine_data.report_id}")
            return MajorProjectState.COMPLETED

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            state_machine_data.error_message = f"Report generation failed: {str(e)}"

            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"**Error during report generation:** {str(e)}",
                    ),
                    trace_id=task_id,
                )

            return MajorProjectState.FAILED