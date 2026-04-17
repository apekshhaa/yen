"""Waiting for target workflow state."""
from __future__ import annotations

from typing import Optional, override
from temporalio import workflow

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


class WaitingForTargetWorkflow(StateWorkflow):
    """Workflow for waiting for user to provide target scope."""

    @override
    async def execute(
        self,
        state_machine: StateMachine,
        state_machine_data: Optional[MajorProjectData] = None,
    ) -> str:
        """
        Wait for user to provide target scope configuration.
        """
        if state_machine_data is None:
            return MajorProjectState.FAILED

        logger.info("Waiting for target scope from user...")

        # Wait for user input using workflow condition
        await workflow.wait_condition(lambda: not state_machine_data.waiting_for_user_input)

        # Check if we have valid target scope (may have been set by main workflow from JSON)
        if state_machine_data.target_scope is None:
            # Try to parse simple domain input from instruction
            instruction = state_machine_data.instruction.strip()

            if instruction:
                # Try to parse as JSON first
                import json
                try:
                    data = json.loads(instruction)
                    if "target_scope" in data:
                        from project.state_machines.major_project_agent import TargetScope
                        state_machine_data.target_scope = TargetScope(**data["target_scope"])
                        if "scan_type" in data:
                            state_machine_data.scan_type = data["scan_type"]
                        logger.info(f"Parsed target scope from JSON: {state_machine_data.target_scope.domains}")
                    else:
                        state_machine_data.error_message = "JSON provided but missing 'target_scope' field."
                        return MajorProjectState.FAILED
                except json.JSONDecodeError:
                    # Not JSON, try to parse as simple domain
                    from project.state_machines.major_project_agent import TargetScope
                    if "." in instruction and " " not in instruction:
                        # Treat as single domain
                        state_machine_data.target_scope = TargetScope(
                            domains=[instruction],
                        )
                        logger.info(f"Auto-configured target scope for: {instruction}")
                    else:
                        state_machine_data.error_message = "Invalid target scope. Please provide a valid domain or JSON configuration."
                        return MajorProjectState.FAILED
            else:
                state_machine_data.error_message = "No target scope provided."
                return MajorProjectState.FAILED

        # Validate target scope
        scope = state_machine_data.target_scope
        if not scope.domains and not scope.ip_ranges:
            state_machine_data.error_message = "Target scope must include at least one domain or IP range."
            return MajorProjectState.FAILED

        # Send confirmation message
        if state_machine_data.task_id:
            targets = ", ".join(scope.domains + scope.ip_ranges)
            excluded = ", ".join(scope.excluded_hosts) if scope.excluded_hosts else "None"

            await adk.messages.create(
                task_id=state_machine_data.task_id,
                content=TextContent(
                    author="agent",
                    content=f"""## Target Scope Validated

**Targets:** {targets}
**Excluded:** {excluded}
**Scan Type:** {state_machine_data.scan_type}
**Rules of Engagement:** {scope.rules_of_engagement or 'Standard'}

Starting reconnaissance phase...""",
                ),
                trace_id=state_machine_data.task_id,
            )

        state_machine_data.scope_validated = True
        logger.info(f"Target scope validated: {scope.domains}")

        # Move to asset discovery
        return MajorProjectState.DISCOVERING_ASSETS
