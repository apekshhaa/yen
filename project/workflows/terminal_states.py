"""Terminal state workflows for Major-Project agent."""
from __future__ import annotations

from typing import Optional, override

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


class CompletedWorkflow(StateWorkflow):
    """Workflow for completed state."""

    @override
    async def execute(
        self,
        state_machine: StateMachine,
        state_machine_data: Optional[MajorProjectData] = None,
    ) -> str:
        """
        Handle successful completion of the penetration test.
        """
        if state_machine_data is None:
            return MajorProjectState.COMPLETED

        logger.info("Penetration test completed successfully")
        task_id = state_machine_data.task_id

        if task_id:
            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content="""## ✅ Assessment Complete

The security assessment has been completed successfully.

**Summary:**
- All phases completed
- Report generated
- Ready for review

Thank you for using Major-Project AI Pentester.""",
                ),
                trace_id=task_id,
            )

        # Reset for next assessment
        state_machine_data.waiting_for_user_input = True

        # Return to waiting for next target
        return MajorProjectState.WAITING_FOR_TARGET


class FailedWorkflow(StateWorkflow):
    """Workflow for failed state."""

    @override
    async def execute(
        self,
        state_machine: StateMachine,
        state_machine_data: Optional[MajorProjectData] = None,
    ) -> str:
        """
        Handle failure during the penetration test.
        """
        if state_machine_data is None:
            return MajorProjectState.FAILED

        logger.error(f"Penetration test failed: {state_machine_data.error_message}")
        task_id = state_machine_data.task_id

        if task_id:
            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content=f"""## ❌ Assessment Failed

The security assessment encountered an error:

**Error:** {state_machine_data.error_message}

Please review the error and try again.""",
                ),
                trace_id=task_id,
            )

        # Reset for retry
        state_machine_data.waiting_for_user_input = True
        state_machine_data.error_message = ""

        # Return to waiting for next target
        return MajorProjectState.WAITING_FOR_TARGET


class PausedForApprovalWorkflow(StateWorkflow):
    """Workflow for paused state waiting for approval."""

    @override
    async def execute(
        self,
        state_machine: StateMachine,
        state_machine_data: Optional[MajorProjectData] = None,
    ) -> str:
        """
        Handle paused state while waiting for human approval.
        """
        if state_machine_data is None:
            return MajorProjectState.PAUSED_FOR_APPROVAL

        logger.info("Assessment paused for approval")
        task_id = state_machine_data.task_id

        if task_id:
            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content="""## ⏸️ Assessment Paused

The assessment is paused pending human approval.

Please provide approval to continue.""",
                ),
                trace_id=task_id,
            )

        # Stay in paused state
        return MajorProjectState.PAUSED_FOR_APPROVAL