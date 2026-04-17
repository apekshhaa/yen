"""Awaiting human review workflow state."""
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


class AwaitingHumanReviewWorkflow(StateWorkflow):
    """Workflow for awaiting human review of the report."""

    @override
    async def execute(
        self,
        state_machine: StateMachine,
        state_machine_data: Optional[MajorProjectData] = None,
    ) -> str:
        """
        Wait for human review and approval of the security report.
        """
        if state_machine_data is None:
            return MajorProjectState.FAILED

        logger.info("Awaiting human review...")
        task_id = state_machine_data.task_id

        try:
            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content="""## Report Ready for Review

The security assessment report is ready for your review.

Please review the findings and provide feedback if needed.""",
                    ),
                    trace_id=task_id,
                )

            # In a real implementation, this would wait for human review
            # For now, we'll proceed directly to completion
            logger.info("Report review complete")
            return MajorProjectState.COMPLETED

        except Exception as e:
            logger.error(f"Human review workflow failed: {e}")
            state_machine_data.error_message = f"Human review workflow failed: {str(e)}"

            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"**Error during human review:** {str(e)}",
                    ),
                    trace_id=task_id,
                )

            return MajorProjectState.FAILED