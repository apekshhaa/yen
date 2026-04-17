"""Gathering threat intelligence workflow state.

This workflow uses an AI-powered threat intelligence agent to dynamically
research CVEs, exploits, and OSINT data based on discovered technologies.
No static CVE mappings - all intelligence is gathered in real-time.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional, override

from temporalio import workflow
from temporalio.common import RetryPolicy

from agentex.lib import adk
from agentex.lib.sdk.state_machine import StateMachine
from agentex.lib.sdk.state_machine.state_workflow import StateWorkflow
from agentex.lib.utils.logging import make_logger
from agentex.types.text_content import TextContent
from project.state_machines.major_project_agent import (
    MajorProjectData,
    MajorProjectState,
    ThreatIntel,
)

logger = make_logger(__name__)

# Import activities with workflow.unsafe context
with workflow.unsafe.imports_passed_through():
    from project.activities.threat_intel_activities import (
        run_threat_intel_agent_activity,
        correlate_vulnerabilities_activity,
    )


class GatheringThreatIntelWorkflow(StateWorkflow):
    """Workflow for gathering threat intelligence about discovered assets.

    This workflow uses an AI-powered threat intelligence agent to:
    1. Research CVEs for discovered technologies
    2. Find publicly available exploits
    3. Gather OSINT data
    4. Correlate findings with assets for prioritized exploitation

    No static CVE mappings are used - all intelligence is dynamically gathered.
    """

    @override
    async def execute(
        self,
        state_machine: StateMachine,
        state_machine_data: Optional[MajorProjectData] = None,
    ) -> str:
        """
        Gather threat intelligence using AI-powered agent.

        The agent dynamically researches:
        - CVEs from NVD and security advisories
        - Exploits from Exploit-DB, GitHub, Metasploit
        - OSINT findings relevant to the technologies
        - Attack recommendations based on severity and exploitability
        """
        if state_machine_data is None:
            return MajorProjectState.FAILED

        logger.info("Starting AI-powered threat intelligence gathering...")
        task_id = state_machine_data.task_id

        try:
            # Initialize threat intel data
            threat_intel = ThreatIntel(last_updated=datetime.utcnow())

            # Collect technologies from discovered assets
            technologies = set()
            for asset in state_machine_data.discovered_assets:
                technologies.update(asset.technologies)

            technologies_list = list(technologies)
            logger.info(f"Gathering threat intelligence for {len(technologies_list)} technologies")

            # Prepare assets data for the agent
            assets_data = []
            for asset in state_machine_data.discovered_assets:
                assets_data.append({
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "ports": asset.ports,
                    "services": asset.services,
                    "technologies": asset.technologies,
                    "web_server": asset.web_server,
                    "operating_system": asset.operating_system,
                })

            # Notify user that AI agent is starting
            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"""## 🔍 AI Threat Intelligence Agent Starting

**Technologies to research:** {len(technologies_list)}
**Assets to analyze:** {len(assets_data)}

The AI agent will dynamically research:
- CVEs from NVD and security advisories
- Exploits from Exploit-DB, GitHub, Metasploit
- OSINT findings and attack vectors
- Prioritized attack recommendations

This replaces static CVE mappings with real-time intelligence gathering...""",
                    ),
                    trace_id=task_id,
                )

            # Run the threat intelligence agent activity
            intel_result = await workflow.execute_activity(
                run_threat_intel_agent_activity,
                args=[technologies_list, assets_data, task_id, task_id],
                start_to_close_timeout=timedelta(seconds=180),  # 3 min for LLM calls
                heartbeat_timeout=timedelta(seconds=60),
                retry_policy=RetryPolicy(maximum_attempts=2),
            )

            # Extract results from the agent
            cves_found = intel_result.get("cves", [])
            exploits_found = intel_result.get("exploits", [])
            osint_findings = intel_result.get("osint_findings", [])
            attack_recommendations = intel_result.get("attack_recommendations", [])

            # Correlate vulnerabilities with assets
            if cves_found:
                correlation_result = await workflow.execute_activity(
                    correlate_vulnerabilities_activity,
                    args=[cves_found, exploits_found, assets_data, task_id, task_id],
                    start_to_close_timeout=timedelta(seconds=60),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )

                # Store prioritized targets for exploitation phase
                prioritized_targets = correlation_result.get("prioritized_targets", [])
                if prioritized_targets:
                    state_machine_data.prioritized_targets = [
                        t.get("asset") for t in prioritized_targets[:10]
                    ]

            # Update threat intel data structure
            threat_intel.cves = cves_found
            threat_intel.exploits_available = exploits_found
            threat_intel.osint_findings = osint_findings
            threat_intel.known_vulnerabilities = [
                {
                    "cve_id": cve.get("cve_id"),
                    "severity": cve.get("severity"),
                    "technology": cve.get("technology"),
                    "exploit_available": cve.get("exploit_available", False),
                }
                for cve in cves_found
            ]

            state_machine_data.threat_intel = threat_intel

            # Count by severity
            critical_count = len([c for c in cves_found if c.get("severity") == "critical"])
            high_count = len([c for c in cves_found if c.get("severity") == "high"])
            exploitable_count = len([c for c in cves_found if c.get("exploit_available")])

            # Send summary
            if task_id:
                recommendations_str = ""
                if attack_recommendations:
                    recommendations_str = "\n\n**🎯 Attack Recommendations:**\n"
                    for rec in attack_recommendations[:5]:
                        recommendations_str += f"- **Priority {rec.get('priority', '?')}:** {rec.get('target')} - {rec.get('vulnerability')} ({rec.get('reason', '')})\n"

                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"""## ✅ AI Threat Intelligence Complete

**CVEs Identified:** {len(cves_found)}
- 🔴 Critical: {critical_count}
- 🟠 High: {high_count}
- ⚡ With Exploits: {exploitable_count}

**Exploits Found:** {len(exploits_found)}
**OSINT Findings:** {len(osint_findings)}
{recommendations_str}
Proceeding to AI-driven vulnerability analysis...""",
                    ),
                    trace_id=task_id,
                )

            logger.info(f"AI threat intel complete: {len(cves_found)} CVEs, {len(exploits_found)} exploits")

            # Proceed to AI-driven vulnerability reasoning
            return MajorProjectState.REASONING_VULNERABILITIES

        except Exception as e:
            logger.error(f"AI threat intel gathering failed: {e}")
            state_machine_data.error_message = f"Threat intel gathering failed: {str(e)}"

            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"**⚠️ Error during AI threat intel gathering:** {str(e)}\n\nContinuing with vulnerability analysis...",
                    ),
                    trace_id=task_id,
                )

            # Continue even if threat intel fails - the AI vulnerability reasoning
            # can still discover vulnerabilities through active testing
            return MajorProjectState.REASONING_VULNERABILITIES
