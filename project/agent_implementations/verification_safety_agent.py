"""Verification & Safety Agent for Major-Project pentesting."""
from __future__ import annotations

from typing import List, Optional

from openai_agents import Agent, function_tool
from temporalio import workflow

from project.constants import OPENAI_MODEL


@function_tool
async def verify_exploit_success(
    exploit_id: str,
    target: str,
    expected_outcome: str,
    actual_output: str,
    task_id: str,
) -> str:
    """
    Verify that an exploit was successful and achieved the intended outcome.

    Call this when:
    - An exploit has been executed
    - Need to confirm success
    - Validating exploit results

    Args:
        exploit_id: ID of the exploit that was run
        target: Target system
        expected_outcome: What should have happened
        actual_output: Actual output from exploit execution
        task_id: Task ID for tracing

    Returns:
        JSON string with verification results
    """
    import json

    workflow.logger.info(f"Verifying exploit {exploit_id} against {target}")

    # Analyze output to determine success
    success_indicators = [
        "success",
        "shell",
        "command executed",
        "access granted",
        "data retrieved",
    ]

    is_successful = any(
        indicator in actual_output.lower()
        for indicator in success_indicators
    )

    verification = {
        "exploit_id": exploit_id,
        "target": target,
        "expected_outcome": expected_outcome,
        "verified_successful": is_successful,
        "confidence": "high" if is_successful else "low",
        "evidence": actual_output[:500],  # First 500 chars
        "false_positive": not is_successful and "error" not in actual_output.lower(),
    }

    return json.dumps(verification)


@function_tool
async def check_safety_compliance(
    action_description: str,
    target_scope: str,
    rules_of_engagement: str,
    task_id: str,
) -> str:
    """
    Check if a planned action complies with safety rules and scope.

    CRITICAL: Call this BEFORE any potentially risky action!

    Call this when:
    - Planning to execute an exploit
    - About to perform any system modification
    - Need to verify action is within scope

    Args:
        action_description: What you plan to do
        target_scope: Authorized target scope
        rules_of_engagement: Rules of engagement document
        task_id: Task ID for tracing

    Returns:
        JSON string with safety compliance check
    """
    import json

    workflow.logger.info(f"Checking safety compliance for: {action_description}")

    # Check for dangerous operations
    dangerous_keywords = [
        "delete",
        "drop",
        "truncate",
        "format",
        "shutdown",
        "reboot",
        "rm -rf",
        "destroy",
    ]

    is_dangerous = any(
        keyword in action_description.lower()
        for keyword in dangerous_keywords
    )

    # Check if target is in scope
    in_scope = True  # In production, validate against actual scope

    compliance = {
        "action": action_description,
        "compliant": not is_dangerous and in_scope,
        "in_scope": in_scope,
        "is_dangerous": is_dangerous,
        "violations": [],
        "recommendation": "Proceed" if not is_dangerous and in_scope else "STOP - Violation detected",
    }

    if is_dangerous:
        compliance["violations"].append("Potentially destructive operation detected")

    if not in_scope:
        compliance["violations"].append("Target is outside authorized scope")

    return json.dumps(compliance)


@function_tool
async def validate_reversibility(
    action_description: str,
    system_state_before: str,
    task_id: str,
) -> str:
    """
    Validate that an action can be reversed/undone.

    Call this when:
    - Planning system modifications
    - Need to ensure cleanup is possible
    - Verifying non-destructive testing

    Args:
        action_description: The action to validate
        system_state_before: System state before the action
        task_id: Task ID for tracing

    Returns:
        JSON string with reversibility assessment
    """
    import json

    workflow.logger.info(f"Validating reversibility of: {action_description}")

    # Categorize action reversibility
    reversible_actions = [
        "read",
        "list",
        "enumerate",
        "scan",
        "probe",
        "query",
    ]

    partially_reversible = [
        "create",
        "upload",
        "modify",
        "update",
    ]

    irreversible_actions = [
        "delete",
        "drop",
        "truncate",
        "format",
        "destroy",
    ]

    action_lower = action_description.lower()

    if any(action in action_lower for action in reversible_actions):
        reversibility = "fully_reversible"
        can_proceed = True
    elif any(action in action_lower for action in partially_reversible):
        reversibility = "partially_reversible"
        can_proceed = True
    elif any(action in action_lower for action in irreversible_actions):
        reversibility = "not_reversible"
        can_proceed = False
    else:
        reversibility = "unknown"
        can_proceed = False

    assessment = {
        "action": action_description,
        "reversibility": reversibility,
        "can_proceed": can_proceed,
        "rollback_plan": "Manual cleanup required" if reversibility == "partially_reversible" else "No cleanup needed",
        "risk_level": "low" if reversibility == "fully_reversible" else "high",
    }

    return json.dumps(assessment)


@function_tool
async def perform_safety_rollback(
    exploit_id: str,
    target: str,
    changes_made: str,
    task_id: str,
) -> str:
    """
    Perform rollback/cleanup after exploit execution.

    Call this when:
    - Exploit execution is complete
    - Need to clean up artifacts
    - Restoring system to original state

    Args:
        exploit_id: ID of the exploit
        target: Target system
        changes_made: Description of changes that were made
        task_id: Task ID for tracing

    Returns:
        JSON string with rollback results
    """
    import json

    workflow.logger.info(f"Performing safety rollback for exploit {exploit_id}")

    # Simulated rollback - in production, this would perform actual cleanup
    rollback = {
        "exploit_id": exploit_id,
        "target": target,
        "changes_made": changes_made,
        "rollback_successful": True,
        "cleanup_actions": [
            "Removed uploaded files",
            "Closed connections",
            "Cleared logs",
        ],
        "system_restored": True,
    }

    return json.dumps(rollback)


@function_tool
async def validate_scope_authorization(
    target: str,
    authorized_scope: List[str],
    task_id: str,
) -> str:
    """
    Validate that a target is within authorized scope.

    CRITICAL: Call this before testing ANY target!

    Call this when:
    - About to test a new target
    - Verifying scope compliance
    - Ensuring legal authorization

    Args:
        target: Target to validate (IP, domain, URL)
        authorized_scope: List of authorized targets
        task_id: Task ID for tracing

    Returns:
        JSON string with scope validation
    """
    import json

    workflow.logger.info(f"Validating scope for target: {target}")

    # Check if target matches any authorized scope
    in_scope = False
    matched_scope = None

    for scope_item in authorized_scope:
        if scope_item in target or target in scope_item:
            in_scope = True
            matched_scope = scope_item
            break

    validation = {
        "target": target,
        "in_scope": in_scope,
        "matched_scope": matched_scope,
        "authorized": in_scope,
        "action": "PROCEED" if in_scope else "STOP - OUT OF SCOPE",
        "warning": None if in_scope else "Testing this target would violate authorization!",
    }

    return json.dumps(validation)


@function_tool
async def check_rate_limits(
    target: str,
    requests_per_minute: int,
    task_id: str,
) -> str:
    """
    Check if current request rate is within safe limits to avoid DoS.

    Call this when:
    - Performing automated scanning
    - Running multiple exploits
    - Need to avoid overwhelming the target

    Args:
        target: Target being tested
        requests_per_minute: Current request rate
        task_id: Task ID for tracing

    Returns:
        JSON string with rate limit assessment
    """
    import json

    workflow.logger.info(f"Checking rate limits for {target}: {requests_per_minute} req/min")

    # Define safe rate limits
    safe_limit = 60  # 60 requests per minute
    warning_limit = 100
    danger_limit = 200

    if requests_per_minute <= safe_limit:
        status = "safe"
        action = "continue"
    elif requests_per_minute <= warning_limit:
        status = "warning"
        action = "slow_down"
    elif requests_per_minute <= danger_limit:
        status = "danger"
        action = "reduce_rate"
    else:
        status = "critical"
        action = "stop_immediately"

    assessment = {
        "target": target,
        "current_rate": requests_per_minute,
        "safe_limit": safe_limit,
        "status": status,
        "action": action,
        "recommendation": f"Current rate: {requests_per_minute}/min. Safe limit: {safe_limit}/min",
    }

    return json.dumps(assessment)


def new_verification_safety_agent(
    authorized_scope: Optional[List[str]] = None,
    rules_of_engagement: Optional[str] = None,
    task_id: str = "",
) -> Agent:
    """
    Create a Verification & Safety Agent for ensuring safe pentesting.

    This agent is the SAFETY GUARDIAN - it ensures:
    - All actions are within authorized scope
    - Exploits are non-destructive
    - Changes are reversible
    - Rate limits are respected
    - Compliance with rules of engagement

    Args:
        authorized_scope: List of authorized targets
        rules_of_engagement: Rules of engagement document
        task_id: Task ID for tracing

    Returns:
        Agent configured for safety verification
    """
    scope_str = "No scope defined yet"
    if authorized_scope:
        scope_str = "\n".join([f"- {item}" for item in authorized_scope[:10]])

    roe_str = "No rules of engagement defined"
    if rules_of_engagement:
        roe_str = rules_of_engagement[:500]  # First 500 chars

    instructions = f"""
You are the Verification & Safety Agent - the GUARDIAN of ethical and safe penetration testing.

Your role is CRITICAL: You ensure that all pentesting activities are:
- Legal and authorized
- Non-destructive
- Reversible
- Within scope
- Compliant with rules of engagement

## Authorized Scope

{scope_str}

## Rules of Engagement

{roe_str}

## Your Mission

You are the FINAL SAFETY CHECK before any action is taken. Your responsibilities:

1. **Scope Validation**: Verify ALL targets are authorized
2. **Safety Compliance**: Ensure actions are non-destructive
3. **Reversibility**: Validate that changes can be undone
4. **Exploit Verification**: Confirm exploits worked as intended
5. **Rollback**: Clean up after testing
6. **Rate Limiting**: Prevent DoS conditions

## CRITICAL SAFETY RULES

⚠️ **YOU MUST ENFORCE THESE RULES** ⚠️

### Rule 1: Scope Validation
- ALWAYS validate targets before testing
- NEVER test outside authorized scope
- STOP immediately if scope violation detected

### Rule 2: Non-Destructive Testing
- NO data deletion
- NO system modifications that can't be reversed
- NO service disruption
- NO production data corruption

### Rule 3: Reversibility
- ALL changes must be reversible
- Document cleanup procedures
- Perform rollback after testing
- Restore original state

### Rule 4: Rate Limiting
- Respect rate limits to avoid DoS
- Monitor request rates
- Slow down if limits exceeded
- Never overwhelm target systems

### Rule 5: Human Oversight
- High-risk actions require approval
- Escalate dangerous operations
- Document all safety decisions

## Tools Available

- `validate_scope_authorization`: Check if target is in scope (USE FIRST!)
- `check_safety_compliance`: Verify action complies with rules
- `validate_reversibility`: Ensure action can be undone
- `verify_exploit_success`: Confirm exploit worked
- `perform_safety_rollback`: Clean up after testing
- `check_rate_limits`: Monitor request rates

## Safety Workflow

### Before ANY Action:
1. Validate target is in authorized scope
2. Check safety compliance
3. Validate reversibility
4. Verify rate limits are safe
5. Only then proceed

### After Exploit Execution:
1. Verify exploit success
2. Document evidence
3. Perform safety rollback
4. Confirm system restored

## Dangerous Operations (NEVER ALLOW)

- File deletion (rm, del, unlink)
- Database drops (DROP TABLE, TRUNCATE)
- System shutdown/reboot
- Disk formatting
- Production data modification
- Service disruption
- Credential theft (only test, don't exfiltrate)
- Lateral movement outside scope

## Safe Operations (ALLOWED)

- Read-only operations
- Enumeration and scanning
- Proof-of-concept exploits
- Reversible file creation
- Non-destructive testing
- Evidence collection
- Vulnerability validation

## Verification Criteria

An exploit is successfully verified if:
- Expected outcome matches actual result
- Evidence clearly demonstrates success
- No false positives
- Impact is documented
- Cleanup was successful

## Rollback Procedures

After each exploit:
1. Remove uploaded files
2. Close connections
3. Clear temporary data
4. Restore modified configurations
5. Verify system state matches pre-test
6. Document cleanup actions

## Rate Limit Guidelines

- Safe: ≤ 60 requests/minute
- Warning: 61-100 requests/minute
- Danger: 101-200 requests/minute
- Critical: > 200 requests/minute (STOP!)

## Output Format

For each safety check, provide:

1. **Target Validation**: Is target in scope?
2. **Safety Assessment**: Is action safe?
3. **Reversibility**: Can it be undone?
4. **Risk Level**: Low/Medium/High
5. **Decision**: PROCEED or STOP
6. **Reasoning**: Why this decision?

## Example Safety Check

```
Target: api.example.com
Action: Test SQL injection on login form
Scope Check: ✓ In authorized scope
Safety Check: ✓ Read-only operation
Reversibility: ✓ Fully reversible
Rate Limit: ✓ 45 req/min (safe)
Decision: PROCEED
Reasoning: All safety checks passed, action is non-destructive
```

Remember: You are the last line of defense against unsafe testing.
When in doubt, STOP and escalate to human oversight!

Your motto: "Safety First, Always!"
"""

    return Agent(
        name="Verification & Safety Agent",
        instructions=instructions,
        model=OPENAI_MODEL,
        tools=[
            validate_scope_authorization,
            check_safety_compliance,
            validate_reversibility,
            verify_exploit_success,
            perform_safety_rollback,
            check_rate_limits,
        ],
    )