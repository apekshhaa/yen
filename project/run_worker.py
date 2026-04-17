"""Temporal worker for Major-Project AI Pentester Agent."""
import asyncio

from temporalio.contrib.openai_agents import OpenAIAgentsPlugin

from agentex.lib.core.temporal.activities import get_all_activities
from agentex.lib.core.temporal.workers.worker import AgentexWorker
from agentex.lib.environment_variables import EnvironmentVariables
from agentex.lib.utils.debug import setup_debug_if_enabled
from agentex.lib.utils.logging import make_logger
from agentex.lib.core.temporal.plugins.openai_agents.hooks.activities import stream_lifecycle_content
from agentex.lib.core.temporal.plugins.openai_agents.models.temporal_streaming_model import (
    TemporalStreamingModelProvider,
)
from agentex.lib.core.temporal.plugins.openai_agents.interceptors.context_interceptor import (
    ContextInterceptor,
)

# Import custom activities
from project.activities.discovery_activities import (
    run_subfinder_activity,
    run_asset_discovery_activity,
    resolve_dns_activity,
)
from project.activities.scanning_activities import (
    run_nmap_scan_activity,
    run_nuclei_scan_activity,
    run_httpx_probe_activity,
    run_technology_detection_activity,
)
from project.activities.exploitation_activities import (
    generate_exploit_activity,
    execute_exploit_activity,
    mutate_payload_activity,
    verify_exploit_activity,
)
from project.activities.reporting_activities import (
    generate_finding_activity,
    generate_report_activity,
    send_notification_activity,
)
from project.activities.ai_reasoning_activities import (
    crawl_application_activity,
    analyze_endpoint_for_vulnerabilities_activity,
    test_vulnerability_activity,
    ai_reason_about_findings_activity,
)
from project.activities.pentest_agent_loop import run_pentest_agent_loop_activity
from project.activities.attack_chain_reasoning import (
    analyze_attack_chains_activity,
    reason_about_chain_exploitability_activity,
    generate_chain_poc_activity,
)
from project.activities.creative_payload_generation import (
    generate_creative_payloads_activity,
)
from project.activities.threat_intel_activities import (
    run_threat_intel_agent_activity,
    correlate_vulnerabilities_activity,
)

# NEW: Continuous Discovery activities
from project.activities.continuous_discovery import (
    continuous_asset_discovery_activity,
    endpoint_change_detection_activity,
    prioritize_scan_targets_activity,
    schedule_continuous_scan_activity,
)

# NEW: Zero-Day Discovery activities
from project.activities.zero_day_discovery import (
    behavioral_anomaly_detection_activity,
    semantic_vulnerability_reasoning_activity,
    intelligent_mutation_fuzzing_activity,
    generate_novel_attack_vectors_activity,
    execute_novel_attack_activity,
)

# NEW: Parallel Testing activities
from project.activities.parallel_testing import (
    parallel_vulnerability_scan_activity,
    prioritize_endpoints_activity,
    coordinate_distributed_scan_activity,
    schedule_continuous_tests_activity,
)

# NEW: Pentest Memory activities
from project.activities.pentest_memory import (
    store_vulnerability_finding_activity,
    get_learned_payloads_activity,
    get_technology_insights_activity,
    get_similar_findings_activity,
    analyze_learning_opportunities_activity,
    get_memory_statistics_activity,
    apply_learned_strategy_activity,
)

# NEW: Exploitation Verification activities
from project.activities.exploitation_verification import (
    verify_vulnerability_finding_activity,
    batch_verify_findings_activity,
    generate_poc_activity,
    measure_impact_activity,
    collect_evidence_activity,
)

# NEW: Comprehensive Reporting activities
from project.activities.comprehensive_reporting import (
    generate_executive_summary_activity,
    generate_technical_report_activity,
    generate_remediation_report_activity,
    generate_trend_report_activity,
    generate_dashboard_data_activity,
)

# NEW: API Discovery activities
from project.activities.api_discovery import (
    discover_openapi_endpoints_activity,
    discover_graphql_endpoints_activity,
    enumerate_api_endpoints_activity,
    detect_api_authentication_activity,
    analyze_api_security_activity,
)

# NEW: Attack Surface History activities
from project.activities.attack_surface_history import (
    save_attack_surface_snapshot_activity,
    get_attack_surface_history_activity,
    detect_attack_surface_changes_activity,
    save_vulnerability_finding_activity,
    get_vulnerability_trends_activity,
)

# NEW: Alerting activities
from project.activities.alerting import (
    send_exposure_alert_activity,
    send_vulnerability_alert_activity,
    send_scan_complete_alert_activity,
    send_change_detection_alert_activity,
    configure_alert_channels_activity,
)

from project.workflow import MajorProjectWorkflow
from project.workflows.continuous_pentest_workflow import ContinuousPentestWorkflow

environment_variables = EnvironmentVariables.refresh()

logger = make_logger(__name__)


async def main():
    """Run the Temporal worker."""
    # Setup debug mode if enabled
    setup_debug_if_enabled()

    task_queue_name = environment_variables.WORKFLOW_TASK_QUEUE
    if task_queue_name is None:
        raise ValueError("WORKFLOW_TASK_QUEUE is not set")

    logger.info(f"Starting Major-Project worker on task queue: {task_queue_name}")

    # ============================================================================
    # STREAMING SETUP: Interceptor + Model Provider for OpenAI Agents SDK
    # ============================================================================
    # 1. ContextInterceptor: Threads task_id through activity headers
    #    - Outbound: Reads _task_id from workflow instance, injects into activity headers
    #    - Inbound: Extracts task_id from headers, sets streaming_task_id ContextVar
    #
    # 2. TemporalStreamingModelProvider: Returns models that stream to Redis in real-time
    #    - TemporalStreamingModel.get_response() streams tokens while maintaining durability
    #    - Uses AgentEx ADK streaming infrastructure (Redis XADD to stream:{task_id})
    context_interceptor = ContextInterceptor()
    temporal_streaming_model_provider = TemporalStreamingModelProvider()

    # Create a worker with OpenAI Agents SDK plugin for real-time streaming
    worker = AgentexWorker(
        task_queue=task_queue_name,
        plugins=[OpenAIAgentsPlugin(model_provider=temporal_streaming_model_provider)],
        interceptors=[context_interceptor],
    )

    # Combine default Agentex activities with our custom activities
    all_activities = get_all_activities() + [
        # Discovery activities
        run_subfinder_activity,
        run_asset_discovery_activity,
        resolve_dns_activity,
        # Scanning activities
        run_nmap_scan_activity,
        run_nuclei_scan_activity,
        run_httpx_probe_activity,
        run_technology_detection_activity,
        # Exploitation activities
        generate_exploit_activity,
        execute_exploit_activity,
        mutate_payload_activity,
        verify_exploit_activity,
        # Reporting activities
        generate_finding_activity,
        generate_report_activity,
        send_notification_activity,
        # AI Reasoning activities
        crawl_application_activity,
        analyze_endpoint_for_vulnerabilities_activity,
        test_vulnerability_activity,
        ai_reason_about_findings_activity,
        # Agentic Loop
        run_pentest_agent_loop_activity,
        # Attack Chain Reasoning activities
        analyze_attack_chains_activity,
        reason_about_chain_exploitability_activity,
        generate_chain_poc_activity,
        # Creative Payload Generation activity
        generate_creative_payloads_activity,
        # Threat Intelligence activities
        run_threat_intel_agent_activity,
        correlate_vulnerabilities_activity,
        # NEW: Continuous Discovery activities
        continuous_asset_discovery_activity,
        endpoint_change_detection_activity,
        prioritize_scan_targets_activity,
        schedule_continuous_scan_activity,
        # NEW: Zero-Day Discovery activities
        behavioral_anomaly_detection_activity,
        semantic_vulnerability_reasoning_activity,
        intelligent_mutation_fuzzing_activity,
        generate_novel_attack_vectors_activity,
        execute_novel_attack_activity,
        # NEW: Parallel Testing activities
        parallel_vulnerability_scan_activity,
        prioritize_endpoints_activity,
        coordinate_distributed_scan_activity,
        schedule_continuous_tests_activity,
        # NEW: Pentest Memory activities
        store_vulnerability_finding_activity,
        get_learned_payloads_activity,
        get_technology_insights_activity,
        get_similar_findings_activity,
        analyze_learning_opportunities_activity,
        get_memory_statistics_activity,
        apply_learned_strategy_activity,
        # NEW: Exploitation Verification activities
        verify_vulnerability_finding_activity,
        batch_verify_findings_activity,
        generate_poc_activity,
        measure_impact_activity,
        collect_evidence_activity,
        # NEW: Comprehensive Reporting activities
        generate_executive_summary_activity,
        generate_technical_report_activity,
        generate_remediation_report_activity,
        generate_trend_report_activity,
        generate_dashboard_data_activity,
        # NEW: API Discovery activities
        discover_openapi_endpoints_activity,
        discover_graphql_endpoints_activity,
        enumerate_api_endpoints_activity,
        detect_api_authentication_activity,
        analyze_api_security_activity,
        # NEW: Attack Surface History activities
        save_attack_surface_snapshot_activity,
        get_attack_surface_history_activity,
        detect_attack_surface_changes_activity,
        save_vulnerability_finding_activity,
        get_vulnerability_trends_activity,
        # NEW: Alerting activities
        send_exposure_alert_activity,
        send_vulnerability_alert_activity,
        send_scan_complete_alert_activity,
        send_change_detection_alert_activity,
        configure_alert_channels_activity,
        # OpenAI Agents SDK streaming lifecycle activity
        stream_lifecycle_content,
    ]

    logger.info(f"Registered {len(all_activities)} activities")

    # Run the worker with both workflows
    await worker.run(
        activities=all_activities,
        workflows=[MajorProjectWorkflow, ContinuousPentestWorkflow],
    )


if __name__ == "__main__":
    asyncio.run(main())
