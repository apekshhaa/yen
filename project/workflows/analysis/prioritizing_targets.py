"""Prioritizing targets workflow state."""
from __future__ import annotations

from datetime import timedelta
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
)

logger = make_logger(__name__)

# Import activities with workflow.unsafe context
with workflow.unsafe.imports_passed_through():
    from project.activities.parallel_testing import (
        prioritize_endpoints_activity,
    )
    from project.activities.continuous_discovery import (
        prioritize_scan_targets_activity,
    )


class PrioritizingTargetsWorkflow(StateWorkflow):
    """Workflow for prioritizing targets based on risk and exploitability."""

    @override
    async def execute(
        self,
        state_machine: StateMachine,
        state_machine_data: Optional[MajorProjectData] = None,
    ) -> str:
        """
        Prioritize targets based on vulnerability severity and exploitability.
        """
        if state_machine_data is None:
            return MajorProjectState.FAILED

        logger.info("Starting target prioritization...")
        task_id = state_machine_data.task_id

        try:
            # ===== AI-POWERED ENDPOINT PRIORITIZATION =====
            # Use AI to prioritize endpoints based on multiple factors
            endpoints = [
                a.hostname or a.ip_address
                for a in state_machine_data.discovered_assets
                if a.hostname or a.ip_address
            ]
            technologies = list(set(
                tech for asset in state_machine_data.discovered_assets
                for tech in asset.technologies
            ))
            previous_findings = [
                {
                    "type": v.name,
                    "severity": v.severity,
                    "endpoint": v.affected_asset,
                }
                for v in state_machine_data.vulnerabilities
            ]

            try:
                priority_result = await workflow.execute_activity(
                    prioritize_endpoints_activity,
                    args=[endpoints, technologies, previous_findings, task_id, task_id],
                    start_to_close_timeout=timedelta(seconds=120),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )

                prioritized_endpoints = priority_result.get("prioritized_endpoints", [])
                logger.info(f"AI prioritized {len(prioritized_endpoints)} endpoints")

            except Exception as e:
                logger.warning(f"AI endpoint prioritization failed: {e}")
                prioritized_endpoints = endpoints

            # Calculate risk scores for each asset
            asset_risks = {}

            for asset in state_machine_data.discovered_assets:
                risk_score = 0.0
                critical_count = 0
                high_count = 0

                # Count vulnerabilities for this asset
                for vuln in state_machine_data.vulnerabilities:
                    if vuln.affected_asset == asset.hostname or vuln.affected_asset == asset.ip_address:
                        if vuln.severity == "critical":
                            critical_count += 1
                            risk_score += 10.0
                        elif vuln.severity == "high":
                            high_count += 1
                            risk_score += 7.0
                        elif vuln.severity == "medium":
                            risk_score += 4.0
                        elif vuln.severity == "low":
                            risk_score += 1.0

                asset.risk_score = risk_score
                asset.critical_count = critical_count
                asset.high_count = high_count
                asset.vulnerability_count = critical_count + high_count

                if risk_score > 0:
                    asset_risks[asset.id] = {
                        "hostname": asset.hostname or asset.ip_address,
                        "risk_score": risk_score,
                        "critical": critical_count,
                        "high": high_count,
                    }

            # Sort assets by risk score
            sorted_assets = sorted(
                asset_risks.items(),
                key=lambda x: x[1]["risk_score"],
                reverse=True
            )

            # Store prioritized targets (combine AI prioritization with risk scores)
            # First add AI-prioritized endpoints
            prioritized_target_ids = []
            for endpoint in prioritized_endpoints[:5]:
                for asset in state_machine_data.discovered_assets:
                    if asset.hostname == endpoint or asset.ip_address == endpoint:
                        if asset.id not in prioritized_target_ids:
                            prioritized_target_ids.append(asset.id)
                        break

            # Then add risk-score based targets
            for asset_id, _ in sorted_assets[:10]:
                if asset_id not in prioritized_target_ids:
                    prioritized_target_ids.append(asset_id)

            state_machine_data.prioritized_targets = prioritized_target_ids[:10]  # Top 10

            # Build risk matrix
            state_machine_data.risk_matrix = {
                "high_risk_assets": len([a for a in asset_risks.values() if a["risk_score"] >= 20]),
                "medium_risk_assets": len([a for a in asset_risks.values() if 10 <= a["risk_score"] < 20]),
                "low_risk_assets": len([a for a in asset_risks.values() if 0 < a["risk_score"] < 10]),
            }

            # Send summary
            if task_id:
                top_targets = sorted_assets[:5]
                target_list = "\n".join([
                    f"- **{data['hostname']}** (Risk: {data['risk_score']:.1f}, Critical: {data['critical']}, High: {data['high']})"
                    for _, data in top_targets
                ])

                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"""## Target Prioritization Complete

**High-Risk Assets:** {state_machine_data.risk_matrix['high_risk_assets']}
**Medium-Risk Assets:** {state_machine_data.risk_matrix['medium_risk_assets']}
**Low-Risk Assets:** {state_machine_data.risk_matrix['low_risk_assets']}

**Top Priority Targets:**
{target_list}

Moving to exploitation phase (requires approval)...""",
                    ),
                    trace_id=task_id,
                )

            logger.info(f"Target prioritization complete: {len(state_machine_data.prioritized_targets)} targets prioritized")

            # Check if we have any high-risk vulnerabilities that need exploitation
            has_exploitable = any(
                vuln.severity in ["critical", "high"] and vuln.exploitability in ["easy", "moderate"]
                for vuln in state_machine_data.vulnerabilities
            )

            if has_exploitable:
                return MajorProjectState.AWAITING_EXPLOIT_APPROVAL
            else:
                # Skip exploitation if no exploitable vulnerabilities
                return MajorProjectState.GENERATING_REPORT

        except Exception as e:
            logger.error(f"Target prioritization failed: {e}")
            state_machine_data.error_message = f"Target prioritization failed: {str(e)}"

            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"**Error during target prioritization:** {str(e)}",
                    ),
                    trace_id=task_id,
                )

            return MajorProjectState.FAILED