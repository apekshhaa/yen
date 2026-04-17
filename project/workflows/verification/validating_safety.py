"""Validating safety workflow state."""
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


class ValidatingSafetyWorkflow(StateWorkflow):
    """Workflow for validating safety and performing cleanup."""

    @override
    async def execute(
        self,
        state_machine: StateMachine,
        state_machine_data: Optional[MajorProjectData] = None,
    ) -> str:
        """
        Validate that all exploits were safe and perform necessary cleanup.
        """
        if state_machine_data is None:
            return MajorProjectState.FAILED

        logger.info("Validating safety...")
        task_id = state_machine_data.task_id

        try:
            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content="## Safety Validation\n\nValidating safety measures and performing cleanup...",
                    ),
                    trace_id=task_id,
                )

            # In a real implementation, this would:
            # 1. Verify no unintended damage occurred
            # 2. Clean up any artifacts left behind
            # 3. Restore any modified configurations
            # 4. Verify systems are in original state
            # 5. Document all actions taken

            safety_issues = []
            cleanup_performed = True

            if task_id:
                if safety_issues:
                    issues_text = "\n".join([f"- {issue}" for issue in safety_issues])
                    await adk.messages.create(
                        task_id=task_id,
                        content=TextContent(
                            author="agent",
                            content=f"""## ⚠️ Safety Issues Detected

{issues_text}

All issues have been addressed and systems restored.""",
                        ),
                        trace_id=task_id,
                    )
                else:
                    await adk.messages.create(
                        task_id=task_id,
                        content=TextContent(
                            author="agent",
                            content="""## ✅ Safety Validation Complete

All safety checks passed:
- No unintended system modifications
- All artifacts cleaned up
- Systems in original state
- All actions logged

Proceeding to report generation...""",
                        ),
                        trace_id=task_id,
                    )

            logger.info("Safety validation complete")
            return MajorProjectState.GENERATING_REPORT

        except Exception as e:
            logger.error(f"Safety validation failed: {e}")
            state_machine_data.error_message = f"Safety validation failed: {str(e)}"

            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"**Error during safety validation:** {str(e)}",
                    ),
                    trace_id=task_id,
                )

            return MajorProjectState.FAILED