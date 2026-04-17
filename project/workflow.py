"""Main workflow for Major-Project AI Pentester Agent."""
import asyncio
import json
import os
from datetime import timedelta
from typing import override, Optional

from temporalio import workflow
from temporalio.common import RetryPolicy

from agentex.lib import adk
from agentex.lib.core.temporal.workflows.workflow import BaseWorkflow
from agentex.lib.core.temporal.types.workflow import SignalName
from agentex.lib.environment_variables import EnvironmentVariables
from agentex.lib.types.acp import CreateTaskParams, SendEventParams
from agentex.lib.utils.logging import make_logger
from agentex.lib.core.temporal.activities.activity_helpers import ActivityHelpers
from agentex.lib.core.temporal.activities.adk.acp.acp_activities import (
    ACPActivityName,
    EventSendParams,
)
from agentex.types.text_content import TextContent
from agentex.types.event import Event

# Access control: Only allow specific emails to use this agent
ALLOWED_EMAILS = [email.strip() for email in os.getenv("ALLOWED_EMAILS", "").split(",") if email.strip()]

from agentex.lib.sdk.state_machine.state import State
from project.state_machines.major_project_agent import (
    MajorProjectData,
    MajorProjectState,
    MajorProjectStateMachine,
)

# Import workflow states
from project.workflows.discovery.waiting_for_target import WaitingForTargetWorkflow
from project.workflows.discovery.discovering_assets import DiscoveringAssetsWorkflow
from project.workflows.discovery.gathering_threat_intel import GatheringThreatIntelWorkflow
from project.workflows.discovery.mapping_attack_surface import MappingAttackSurfaceWorkflow
from project.workflows.analysis.reasoning_vulnerabilities import ReasoningVulnerabilitiesWorkflow
from project.workflows.analysis.ai_vulnerability_reasoning import AIVulnerabilityReasoningWorkflow
from project.workflows.analysis.prioritizing_targets import PrioritizingTargetsWorkflow
from project.workflows.exploitation.awaiting_exploit_approval import AwaitingExploitApprovalWorkflow
from project.workflows.exploitation.generating_exploits import GeneratingExploitsWorkflow
from project.workflows.exploitation.mutating_payloads import MutatingPayloadsWorkflow
from project.workflows.verification.verifying_exploits import VerifyingExploitsWorkflow
from project.workflows.verification.validating_safety import ValidatingSafetyWorkflow
from project.workflows.reporting.generating_report import GeneratingReportWorkflow
from project.workflows.reporting.awaiting_human_review import AwaitingHumanReviewWorkflow
from project.workflows.terminal_states import CompletedWorkflow, FailedWorkflow, PausedForApprovalWorkflow

environment_variables = EnvironmentVariables.refresh()

if environment_variables.WORKFLOW_NAME is None:
    raise ValueError("Environment variable WORKFLOW_NAME is not set")

if environment_variables.AGENT_NAME is None:
    raise ValueError("Environment variable AGENT_NAME is not set")

logger = make_logger(__name__)


@workflow.defn(name=environment_variables.WORKFLOW_NAME)
class MajorProjectWorkflow(BaseWorkflow):
    """
    Major-Project AI Pentester Workflow using State Machine.
    Orchestrates multi-agent penetration testing with safety guardrails.
    """

    def __init__(self):
        """Initialize the Major-Project workflow with state machine."""
        super().__init__(display_name=environment_variables.AGENT_NAME)

        # Initialize state machine with all states
        self.state_machine = MajorProjectStateMachine(
            initial_state=MajorProjectState.WAITING_FOR_TARGET,
            states=[
                # Discovery Phase
                State(
                    name=MajorProjectState.WAITING_FOR_TARGET,
                    workflow=WaitingForTargetWorkflow(),
                ),
                State(
                    name=MajorProjectState.DISCOVERING_ASSETS,
                    workflow=DiscoveringAssetsWorkflow(),
                ),
                State(
                    name=MajorProjectState.GATHERING_THREAT_INTEL,
                    workflow=GatheringThreatIntelWorkflow(),
                ),
                State(
                    name=MajorProjectState.MAPPING_ATTACK_SURFACE,
                    workflow=MappingAttackSurfaceWorkflow(),
                ),
                # Analysis Phase - AI-Driven Vulnerability Discovery
                State(
                    name=MajorProjectState.REASONING_VULNERABILITIES,
                    workflow=AIVulnerabilityReasoningWorkflow(),  # AI reasoning instead of nuclei-only
                ),
                State(
                    name=MajorProjectState.PRIORITIZING_TARGETS,
                    workflow=PrioritizingTargetsWorkflow(),
                ),
                # Exploitation Phase
                State(
                    name=MajorProjectState.AWAITING_EXPLOIT_APPROVAL,
                    workflow=AwaitingExploitApprovalWorkflow(),
                ),
                State(
                    name=MajorProjectState.GENERATING_EXPLOITS,
                    workflow=GeneratingExploitsWorkflow(),
                ),
                State(
                    name=MajorProjectState.MUTATING_PAYLOADS,
                    workflow=MutatingPayloadsWorkflow(),
                ),
                # Verification Phase
                State(
                    name=MajorProjectState.VERIFYING_EXPLOITS,
                    workflow=VerifyingExploitsWorkflow(),
                ),
                State(
                    name=MajorProjectState.VALIDATING_SAFETY,
                    workflow=ValidatingSafetyWorkflow(),
                ),
                # Reporting Phase
                State(
                    name=MajorProjectState.GENERATING_REPORT,
                    workflow=GeneratingReportWorkflow(),
                ),
                State(
                    name=MajorProjectState.AWAITING_HUMAN_REVIEW,
                    workflow=AwaitingHumanReviewWorkflow(),
                ),
                # Terminal States
                State(
                    name=MajorProjectState.COMPLETED,
                    workflow=CompletedWorkflow(),
                ),
                State(
                    name=MajorProjectState.FAILED,
                    workflow=FailedWorkflow(),
                ),
                State(
                    name=MajorProjectState.PAUSED_FOR_APPROVAL,
                    workflow=PausedForApprovalWorkflow(),
                ),
            ],
            state_machine_data=MajorProjectData(),
            trace_transitions=True,
        )

    @override
    @workflow.signal(name=SignalName.RECEIVE_EVENT)
    async def on_task_event_send(self, params: SendEventParams) -> None:
        """
        Handle incoming events from user.
        Processes target scope, human approvals, and commands.
        """
        state_data = self.state_machine.get_state_machine_data()
        message = params.event.content
        logger.info(f"Received event: {message}")

        try:
            content = message.content if hasattr(message, "content") else str(message)

            # Store the raw content
            state_data.instruction = content if isinstance(content, str) else str(content)

            # Try to parse as JSON for structured input
            if isinstance(content, str):
                try:
                    data = json.loads(content)

                    # Check for coordinator pattern
                    if "coordinator_task_id" in data:
                        state_data.coordinator_task_id = data.get("coordinator_task_id")
                        state_data.worker_task_id = data.get("worker_task_id")

                    # Check for target scope configuration
                    if "target_scope" in data:
                        from project.state_machines.major_project_agent import TargetScope
                        state_data.target_scope = TargetScope(**data["target_scope"])
                        logger.info(f"Target scope configured: {state_data.target_scope.domains}")

                    # Check for human approval response
                    if "approval" in data:
                        approval = data["approval"]
                        if approval.get("approved"):
                            state_data.waiting_for_approval = False
                            logger.info(f"Approval received from: {approval.get('approved_by')}")
                        else:
                            state_data.waiting_for_approval = False
                            state_data.error_message = f"Rejected: {approval.get('reason', 'No reason provided')}"

                    # Check for scan type
                    if "scan_type" in data:
                        state_data.scan_type = data["scan_type"]

                except json.JSONDecodeError:
                    # Plain text input - treat as simple domain/target
                    pass

            logger.info(f"Stored user input: {state_data.instruction[:100]}...")

            # Signal readiness to proceed
            state_data.waiting_for_user_input = False

        except Exception as e:
            logger.error(f"Error processing event: {e}")
            state_data.error_message = str(e)

    @override
    @workflow.run
    async def on_task_create(self, params: CreateTaskParams) -> None:
        """Handle task creation and orchestrate state machine."""
        logger.info(f"Major-Project task created: {params.task.id}")

        # Access control: Check if user email is allowed
        user_email = None
        if params.task.task_metadata:
            user_email = params.task.task_metadata.get("user_email")

        if ALLOWED_EMAILS and user_email not in ALLOWED_EMAILS:
            logger.warning(f"Access denied for email: {user_email}. Allowed emails: {ALLOWED_EMAILS}")
            await adk.messages.create(
                task_id=params.task.id,
                content=TextContent(
                    author="agent",
                    content=f"""# Access Denied

You do not have permission to use the Major-Project AI Pentester agent.

This agent is restricted to authorized users only. If you believe you should have access, please contact the administrator.
""",
                ),
                trace_id=params.task.id,
            )
            return

        # Set task ID in state machine
        self.state_machine.set_task_id(params.task.id)

        state_data = self.state_machine.get_state_machine_data()
        state_data.task_id = params.task.id
        state_data.trace_id = params.task.id
        state_data.waiting_for_user_input = True

        # Send welcome message
        await adk.messages.create(
            task_id=params.task.id,
            content=TextContent(
                author="agent",
                content="""# Major-Project AI Pentester

Welcome to **Major-Project**, your AI-powered continuous penetration testing agent.

## Getting Started

Please provide your target scope in JSON format:

```json
{
  "target_scope": {
    "domains": ["example.com", "*.example.com"],
    "ip_ranges": ["192.168.1.0/24"],
    "excluded_hosts": ["prod-db.example.com"],
    "authorized_until": "2024-12-31T23:59:59Z",
    "rules_of_engagement": "No DoS, testing window 00:00-06:00 UTC"
  },
  "scan_type": "standard"
}
```

**Scan Types:**
- `passive` - Passive reconnaissance only
- `light` - Limited active scanning
- `standard` - Standard penetration test
- `aggressive` - Full aggressive scanning

I will ask for your approval before attempting any high-impact exploits.""",
            ),
            trace_id=params.task.id,
        )

        try:
            # Run the state machine
            await self.state_machine.run()

            # When workflow completes, send result back to coordinator if needed
            if state_data.coordinator_task_id:
                logger.info(f"Sending results back to coordinator: {state_data.coordinator_task_id}")

                result_payload = {
                    "worker_task_id": state_data.worker_task_id or params.task.id,
                    "result": state_data.result,
                    "findings_count": len(state_data.findings),
                    "vulnerabilities_count": len(state_data.vulnerabilities),
                }

                await ActivityHelpers.execute_activity(
                    activity_name=ACPActivityName.EVENT_SEND,
                    request=EventSendParams(
                        task_id=state_data.coordinator_task_id,
                        agent_name="core-orchestrator-agent",
                        content=TextContent(author="agent", content=json.dumps(result_payload)),
                        trace_id=params.task.id,
                    ),
                    response_type=Event,
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(maximum_attempts=3),
                )
                logger.info("Successfully sent results to coordinator")

        except asyncio.CancelledError:
            logger.info("Workflow cancelled")
            raise
        except Exception as e:
            logger.error(f"Workflow error: {e}")
            raise
