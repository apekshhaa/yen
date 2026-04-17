"""Reasoning vulnerabilities workflow state."""
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
    Vulnerability,
)

logger = make_logger(__name__)

# Import activities with workflow.unsafe context
with workflow.unsafe.imports_passed_through():
    from project.activities.scanning_activities import run_nuclei_scan_activity


class ReasoningVulnerabilitiesWorkflow(StateWorkflow):
    """Workflow for analyzing and reasoning about vulnerabilities."""

    @override
    async def execute(
        self,
        state_machine: StateMachine,
        state_machine_data: Optional[MajorProjectData] = None,
    ) -> str:
        """
        Analyze discovered assets and reason about potential vulnerabilities.
        """
        if state_machine_data is None:
            return MajorProjectState.FAILED

        logger.info("Starting vulnerability reasoning phase...")
        task_id = state_machine_data.task_id

        try:
            # Run vulnerability scanning with nuclei
            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=ToolRequestContent(
                        author="agent",
                        name="nuclei_scan",
                        arguments={"assets": len(state_machine_data.discovered_assets)},
                        tool_call_id=f"nuclei_scan_{len(state_machine_data.discovered_assets)}",
                    ),
                    trace_id=task_id,
                )

            # Prepare targets for nuclei - detect protocol from discovered services
            targets = []
            for asset in state_machine_data.discovered_assets[:20]:  # Limit to 20
                host = asset.hostname or asset.ip_address
                if not host:
                    continue

                logger.info(f"Processing asset: {host}, ports: {asset.ports}")

                # Determine protocols based on discovered ports
                if asset.ports:
                    # Add HTTP targets for common HTTP ports
                    http_ports = {80, 8080, 8000, 3000, 8008, 8888, 5000, 9000}
                    https_ports = {443, 8443}

                    for port in asset.ports:
                        if port in http_ports:
                            if port == 80:
                                targets.append(f"http://{host}")
                            else:
                                targets.append(f"http://{host}:{port}")
                        elif port in https_ports:
                            if port == 443:
                                targets.append(f"https://{host}")
                            else:
                                targets.append(f"https://{host}:{port}")
                        else:
                            # Unknown port - try HTTP by default (common for web apps)
                            targets.append(f"http://{host}:{port}")
                else:
                    # No ports discovered - try both HTTP and HTTPS on standard ports
                    targets.append(f"http://{host}")
                    targets.append(f"https://{host}")

            # Deduplicate targets
            targets = list(dict.fromkeys(targets))

            logger.info(f"Generated {len(targets)} targets for nuclei: {targets[:10]}")

            if targets:
                nuclei_result = await workflow.execute_activity(
                    run_nuclei_scan_activity,
                    args=[targets, "cves,vulnerabilities", task_id, task_id],
                    start_to_close_timeout=timedelta(seconds=300),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )

                # Log any scan errors
                if nuclei_result.get("error"):
                    logger.warning(f"Nuclei scan encountered an error: {nuclei_result['error']}")
                    if task_id:
                        await adk.messages.create(
                            task_id=task_id,
                            content=TextContent(
                                author="agent",
                                content=f"⚠️ **Scanner Warning:** {nuclei_result['error']}",
                            ),
                            trace_id=task_id,
                        )

                # Process nuclei results
                for vuln_data in nuclei_result.get("vulnerabilities", []):
                    vuln = Vulnerability(
                        id=str(uuid.uuid4()),
                        name=vuln_data.get("name", "Unknown"),
                        severity=vuln_data.get("severity", "info"),
                        cvss_score=vuln_data.get("cvss_score"),
                        affected_asset=vuln_data.get("host", ""),
                        description=vuln_data.get("description", ""),
                        evidence=vuln_data.get("evidence", ""),
                        scanner="nuclei",
                        discovered_at=datetime.utcnow(),
                    )
                    state_machine_data.vulnerabilities.append(vuln)

                if task_id:
                    await adk.messages.create(
                        task_id=task_id,
                        content=ToolResponseContent(
                            author="agent",
                            tool_call_id=f"nuclei_scan_{len(targets)}",
                            name="nuclei_scan",
                            content=f"Found {len(nuclei_result.get('vulnerabilities', []))} vulnerabilities",
                        ),
                        trace_id=task_id,
                    )

            # Analyze threat intelligence for additional vulnerabilities
            if state_machine_data.threat_intel:
                for cve in state_machine_data.threat_intel.cves:
                    # Create vulnerability from CVE
                    vuln = Vulnerability(
                        id=str(uuid.uuid4()),
                        name=cve.get("cve_id", "Unknown CVE"),
                        severity=cve.get("severity", "medium"),
                        cve_ids=[cve.get("cve_id", "")],
                        description=cve.get("description", ""),
                        scanner="threat_intel",
                        discovered_at=datetime.utcnow(),
                    )
                    state_machine_data.vulnerabilities.append(vuln)

            # Update statistics
            state_machine_data.stats["vulnerabilities_found"] = len(state_machine_data.vulnerabilities)

            # Count by severity
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for vuln in state_machine_data.vulnerabilities:
                if vuln.severity in severity_counts:
                    severity_counts[vuln.severity] += 1

            # Send summary
            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"""## Vulnerability Analysis Complete

**Total Vulnerabilities:** {len(state_machine_data.vulnerabilities)}

**By Severity:**
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Info: {severity_counts['info']}

Proceeding to target prioritization...""",
                    ),
                    trace_id=task_id,
                )

            logger.info(f"Vulnerability reasoning complete: {len(state_machine_data.vulnerabilities)} vulnerabilities found")
            return MajorProjectState.PRIORITIZING_TARGETS

        except Exception as e:
            logger.error(f"Vulnerability reasoning failed: {e}")
            state_machine_data.error_message = f"Vulnerability reasoning failed: {str(e)}"

            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"**Error during vulnerability analysis:** {str(e)}",
                    ),
                    trace_id=task_id,
                )

            return MajorProjectState.FAILED