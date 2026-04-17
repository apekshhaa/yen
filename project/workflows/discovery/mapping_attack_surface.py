"""Mapping attack surface workflow state."""
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
from agentex.types.tool_request_content import ToolRequestContent
from agentex.types.tool_response_content import ToolResponseContent
from project.state_machines.major_project_agent import (
    MajorProjectData,
    MajorProjectState,
)

logger = make_logger(__name__)

# Import activities with workflow.unsafe context
with workflow.unsafe.imports_passed_through():
    from project.activities.scanning_activities import (
        run_nmap_scan_activity,
        run_httpx_probe_activity,
        run_technology_detection_activity,
    )
    from project.activities.api_discovery import (
        discover_openapi_endpoints_activity,
        discover_graphql_endpoints_activity,
        enumerate_api_endpoints_activity,
        detect_api_authentication_activity,
    )
    from project.activities.attack_surface_history import (
        save_attack_surface_snapshot_activity,
        detect_attack_surface_changes_activity,
    )
    from project.activities.alerting import (
        send_change_detection_alert_activity,
        send_exposure_alert_activity,
    )


class MappingAttackSurfaceWorkflow(StateWorkflow):
    """Workflow for mapping attack surface using port scanning and service detection."""

    @override
    async def execute(
        self,
        state_machine: StateMachine,
        state_machine_data: Optional[MajorProjectData] = None,
    ) -> str:
        """
        Map attack surface: port scan, service detection, technology fingerprinting.
        """
        if state_machine_data is None:
            return MajorProjectState.FAILED

        logger.info("Starting attack surface mapping...")
        task_id = state_machine_data.task_id
        scan_type = state_machine_data.scan_type

        try:
            # Determine scan intensity based on scan_type
            if scan_type == "passive":
                # Skip active scanning for passive mode
                if task_id:
                    await adk.messages.create(
                        task_id=task_id,
                        content=TextContent(
                            author="agent",
                            content="**Passive mode:** Skipping active port scanning. Moving to vulnerability analysis...",
                        ),
                        trace_id=task_id,
                    )
                state_machine_data.attack_surface_mapped = True
                return MajorProjectState.REASONING_VULNERABILITIES

            # Configure scan parameters based on scan_type
            if scan_type == "light":
                ports = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"
                scan_options = "-sV -T3"
            elif scan_type == "aggressive":
                ports = "1-65535"
                scan_options = "-sV -sC -A -T4"
            elif scan_type == "stealth":
                ports = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"
                scan_options = "-sS -T2"
            else:  # standard
                ports = "1-10000"
                scan_options = "-sV -sC -T3"

            total_ports_scanned = 0
            total_services_found = 0

            # Process assets in batches
            assets_to_scan = [a for a in state_machine_data.discovered_assets if a.ip_address or a.hostname]

            for i, asset in enumerate(assets_to_scan[:20]):  # Limit to 20 assets
                target = asset.ip_address or asset.hostname

                # Preserve any pre-populated ports (from user-specified domain:port)
                pre_populated_ports = set(asset.ports) if asset.ports else set()

                logger.info(f"Running nmap scan on {target} (pre-populated ports: {pre_populated_ports})")

                # Run nmap scan
                nmap_result = await workflow.execute_activity(
                    run_nmap_scan_activity,
                    args=[target, ports, scan_options, task_id, task_id],
                    start_to_close_timeout=timedelta(seconds=300),
                    retry_policy=RetryPolicy(
                        maximum_attempts=2,
                        initial_interval=timedelta(seconds=5),
                    ),
                )

                # Log any scan errors
                if nmap_result.get("error"):
                    logger.warning(f"Nmap scan error for {target}: {nmap_result['error']}")
                    if task_id:
                        await adk.messages.create(
                            task_id=task_id,
                            content=TextContent(
                                author="agent",
                                content=f"⚠️ **Port scan warning for {target}:** {nmap_result['error']}",
                            ),
                            trace_id=task_id,
                        )

                # Update asset with scan results - MERGE with pre-populated ports
                services = nmap_result.get("services", [])
                discovered_ports = {s.get("port") for s in services if s.get("state") == "open"}
                asset.ports = list(pre_populated_ports | discovered_ports)  # Merge ports
                asset.services = services

                total_ports_scanned += nmap_result.get("ports_scanned", 0)
                total_services_found += len(services)

                logger.info(f"Nmap scan complete for {target}: {len(discovered_ports)} discovered + {len(pre_populated_ports)} pre-populated = {len(asset.ports)} total ports")

            # HTTP probing for web services
            web_assets = [a for a in assets_to_scan if a.has_web_services() or not a.ports]

            if web_assets:
                logger.info(f"Probing {len(web_assets)} web assets with httpx")

                hosts = [a.hostname or a.ip_address for a in web_assets[:50]]
                httpx_result = await workflow.execute_activity(
                    run_httpx_probe_activity,
                    args=[hosts, task_id, task_id],
                    start_to_close_timeout=timedelta(seconds=120),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )

                # Log any httpx errors
                if httpx_result.get("error"):
                    logger.warning(f"Httpx probe error: {httpx_result['error']}")

                # Update assets with web server info
                for probe in httpx_result.get("probes", []):
                    for asset in web_assets:
                        if asset.hostname == probe.get("host") or asset.ip_address == probe.get("host"):
                            asset.web_server = probe.get("server")
                            if probe.get("technologies"):
                                asset.technologies.extend(probe.get("technologies", []))

                logger.info(f"Httpx probe complete: {len(httpx_result.get('probes', []))} web servers found")

            # Technology detection
            logger.info(f"Detecting technologies for {len(assets_to_scan)} assets")

            tech_result = await workflow.execute_activity(
                run_technology_detection_activity,
                args=[[a.hostname or a.ip_address for a in assets_to_scan[:20]], task_id, task_id],
                start_to_close_timeout=timedelta(seconds=180),
                retry_policy=RetryPolicy(maximum_attempts=2),
            )

            # Log any technology detection errors
            if tech_result.get("error"):
                logger.warning(f"Technology detection error: {tech_result['error']}")

            # Update assets with detected technologies
            for detection in tech_result.get("detections", []):
                for asset in assets_to_scan:
                    if asset.hostname == detection.get("host") or asset.ip_address == detection.get("host"):
                        asset.technologies = list(set(asset.technologies + detection.get("technologies", [])))
                        if detection.get("os"):
                            asset.operating_system = detection.get("os")

            logger.info(f"Technology detection complete: {len(tech_result.get('detections', []))} detections")

            # API Discovery - Find OpenAPI, GraphQL, and REST endpoints
            api_endpoints = []
            openapi_specs = []
            graphql_endpoints = []

            for asset in web_assets[:10]:  # Limit to 10 web assets for API discovery
                base_url = f"https://{asset.hostname or asset.ip_address}"

                # Discover OpenAPI/Swagger endpoints
                try:
                    openapi_result = await workflow.execute_activity(
                        discover_openapi_endpoints_activity,
                        args=[base_url, task_id, task_id],
                        start_to_close_timeout=timedelta(seconds=60),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )

                    if openapi_result.get("discovered_specs"):
                        openapi_specs.extend(openapi_result.get("discovered_specs", []))
                        api_endpoints.extend(openapi_result.get("endpoints", []))
                        logger.info(f"Found {len(openapi_result.get('endpoints', []))} OpenAPI endpoints for {base_url}")
                except Exception as e:
                    logger.debug(f"OpenAPI discovery failed for {base_url}: {e}")

                # Discover GraphQL endpoints
                try:
                    graphql_result = await workflow.execute_activity(
                        discover_graphql_endpoints_activity,
                        args=[base_url, task_id, task_id],
                        start_to_close_timeout=timedelta(seconds=60),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )

                    if graphql_result.get("discovered_endpoints"):
                        graphql_endpoints.extend(graphql_result.get("discovered_endpoints", []))
                        logger.info(f"Found {len(graphql_result.get('discovered_endpoints', []))} GraphQL endpoints for {base_url}")
                except Exception as e:
                    logger.debug(f"GraphQL discovery failed for {base_url}: {e}")

                # ===== ENUMERATE REST API ENDPOINTS =====
                # Discover additional REST API endpoints through crawling and pattern matching
                # Collect known endpoints from OpenAPI discovery for this asset
                known_endpoints_for_asset = [
                    e.get("path", e) if isinstance(e, dict) else e
                    for e in api_endpoints
                ]
                try:
                    enumerate_result = await workflow.execute_activity(
                        enumerate_api_endpoints_activity,
                        args=[base_url, known_endpoints_for_asset, task_id, task_id],
                        start_to_close_timeout=timedelta(seconds=90),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )

                    enumerated_endpoints = enumerate_result.get("discovered_endpoints", [])
                    if enumerated_endpoints:
                        api_endpoints.extend(enumerated_endpoints)
                        logger.info(f"Enumerated {len(enumerated_endpoints)} REST API endpoints for {base_url}")
                except Exception as e:
                    logger.debug(f"API enumeration failed for {base_url}: {e}")

                # ===== DETECT API AUTHENTICATION =====
                # Identify authentication mechanisms on discovered APIs
                # Use all endpoints discovered so far for this asset
                endpoints_to_test = []
                for ep in api_endpoints[-30:]:  # Get last 30 endpoints (most recent for this asset)
                    if isinstance(ep, dict):
                        endpoints_to_test.append(ep.get("path", ""))
                    else:
                        endpoints_to_test.append(str(ep))
                # Filter out empty strings
                endpoints_to_test = [ep for ep in endpoints_to_test if ep]

                if endpoints_to_test:
                    try:
                        auth_result = await workflow.execute_activity(
                            detect_api_authentication_activity,
                            args=[base_url, endpoints_to_test[:20], task_id, task_id],
                            start_to_close_timeout=timedelta(seconds=60),
                            retry_policy=RetryPolicy(maximum_attempts=1),
                        )

                        # The activity returns auth_findings and summary, not auth_mechanisms
                        auth_findings = auth_result.get("auth_findings", [])
                        auth_summary = auth_result.get("summary", {})

                        if auth_findings:
                            state_machine_data.stats["api_auth_findings"] = auth_findings
                            state_machine_data.stats["api_auth_summary"] = auth_summary
                            logger.info(f"Tested {len(auth_findings)} endpoints for authentication on {base_url}")

                            # Store auth info for vulnerability analysis
                            for asset in web_assets:
                                if asset.hostname in base_url or (asset.ip_address and asset.ip_address in base_url):
                                    if not hasattr(asset, 'api_auth'):
                                        asset.api_auth = []
                                    asset.api_auth = auth_findings
                    except Exception as e:
                        logger.debug(f"API authentication detection failed for {base_url}: {e}")
                else:
                    logger.debug(f"No endpoints to test for authentication on {base_url}")

            # Store API discovery results in state
            state_machine_data.stats["api_endpoints_discovered"] = len(api_endpoints)
            state_machine_data.stats["openapi_specs_found"] = len(openapi_specs)
            state_machine_data.stats["graphql_endpoints_found"] = len(graphql_endpoints)

            logger.info(f"API discovery complete: {len(api_endpoints)} endpoints, {len(openapi_specs)} OpenAPI specs, {len(graphql_endpoints)} GraphQL endpoints")

            # Update statistics
            state_machine_data.stats["ports_scanned"] = total_ports_scanned
            state_machine_data.attack_surface_mapped = True

            # Send summary
            if task_id:
                # Build attack surface summary
                all_technologies = set()
                all_services = []
                for asset in state_machine_data.discovered_assets:
                    all_technologies.update(asset.technologies)
                    for service in asset.services:
                        if service.get("state") == "open":
                            all_services.append({
                                "host": asset.hostname or asset.ip_address,
                                "port": service.get("port"),
                                "service": service.get("service", "unknown"),
                                "version": service.get("version", ""),
                            })

                # Build services table
                services_table = []
                for svc in all_services[:20]:  # Show first 20 services
                    version_info = f" ({svc['version']})" if svc['version'] else ""
                    services_table.append(f"| `{svc['host']}` | {svc['port']} | {svc['service']}{version_info} |")

                # Build assets with ports summary
                assets_with_ports = []
                for asset in state_machine_data.discovered_assets[:15]:
                    if asset.ports:
                        ports_str = ', '.join(map(str, asset.ports[:10]))
                        if len(asset.ports) > 10:
                            ports_str += f" (+{len(asset.ports) - 10} more)"
                        tech_str = ', '.join(asset.technologies[:3]) if asset.technologies else "N/A"
                        assets_with_ports.append(f"| `{asset.hostname or asset.ip_address}` | {ports_str} | {tech_str} |")

                # Build API discovery summary
                api_summary = ""
                if openapi_specs or graphql_endpoints or api_endpoints:
                    api_summary = f"""

### 🔌 API Discovery
| API Type | Count |
|----------|-------|
| **OpenAPI/Swagger Specs** | {len(openapi_specs)} |
| **GraphQL Endpoints** | {len(graphql_endpoints)} |
| **REST API Endpoints** | {len(api_endpoints)} |
"""
                    if openapi_specs:
                        api_summary += f"""
**OpenAPI Specifications Found:**
{chr(10).join([f"- `{s.get('url', 'Unknown')}` - {s.get('title', 'Untitled')} (v{s.get('version', '?')})" for s in openapi_specs[:5]])}
"""
                    if graphql_endpoints:
                        api_summary += f"""
**GraphQL Endpoints:**
{chr(10).join([f"- `{e.get('url', 'Unknown')}` {'⚠️ Introspection Enabled' if e.get('introspection_enabled') else ''}" for e in graphql_endpoints[:5]])}
"""

                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"""## 🗺️ Attack Surface Mapping Complete

### Summary
| Metric | Count |
|--------|-------|
| **Assets Scanned** | {len(assets_to_scan)} |
| **Open Ports Found** | {sum(len(a.ports) for a in state_machine_data.discovered_assets)} |
| **Services Identified** | {total_services_found} |
| **Technologies Detected** | {len(all_technologies)} |
| **API Endpoints** | {len(api_endpoints)} |

### Discovered Services
| Host | Port | Service |
|------|------|---------|
{chr(10).join(services_table) if services_table else "| No services found | - | - |"}
{f'{chr(10)}*...and {len(all_services) - 20} more services*' if len(all_services) > 20 else ''}

### Assets Overview
| Host | Open Ports | Technologies |
|------|------------|--------------|
{chr(10).join(assets_with_ports) if assets_with_ports else "| No assets with open ports | - | - |"}

### Detected Technologies
{chr(10).join([f'- `{t}`' for t in sorted(list(all_technologies))[:20]]) if all_technologies else "- No technologies detected"}
{f'{chr(10)}*...and {len(all_technologies) - 20} more technologies*' if len(all_technologies) > 20 else ''}
{api_summary}
---
*Proceeding to threat intelligence gathering...*""",
                    ),
                    trace_id=task_id,
                )

            # ===== SAVE ATTACK SURFACE SNAPSHOT =====
            # Save the current attack surface state for change detection
            try:
                organization_id = state_machine_data.target_scope.domains[0] if state_machine_data.target_scope else "unknown"

                # Build attack surface data
                attack_surface_data = {
                    "domains": [asset.hostname for asset in state_machine_data.discovered_assets if asset.hostname],
                    "subdomains": [asset.hostname for asset in state_machine_data.discovered_assets if asset.hostname and '.' in asset.hostname],
                    "ip_addresses": [asset.ip_address for asset in state_machine_data.discovered_assets if asset.ip_address],
                    "services": all_services,
                    "technologies": list(all_technologies),
                    "api_endpoints": api_endpoints,
                    "openapi_specs": openapi_specs,
                    "graphql_endpoints": graphql_endpoints,
                }

                # Detect changes from previous snapshot
                change_result = await workflow.execute_activity(
                    detect_attack_surface_changes_activity,
                    args=[organization_id, attack_surface_data, task_id, task_id],
                    start_to_close_timeout=timedelta(seconds=60),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )

                changes = change_result.get("changes", {})
                has_changes = change_result.get("has_changes", False)

                # Save the new snapshot
                await workflow.execute_activity(
                    save_attack_surface_snapshot_activity,
                    args=[organization_id, attack_surface_data, task_id, task_id],
                    start_to_close_timeout=timedelta(seconds=60),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )

                # Alert on significant changes
                if has_changes:
                    new_assets = changes.get("new_domains", []) + changes.get("new_subdomains", [])
                    new_services = changes.get("new_services", [])

                    if new_assets or new_services:
                        await workflow.execute_activity(
                            send_change_detection_alert_activity,
                            args=[
                                organization_id,
                                {
                                    "new_assets": new_assets[:10],
                                    "new_services": new_services[:10],
                                    "removed_assets": changes.get("removed_domains", [])[:5],
                                    "total_changes": len(new_assets) + len(new_services),
                                },
                                task_id,
                                task_id,
                            ],
                            start_to_close_timeout=timedelta(seconds=30),
                            retry_policy=RetryPolicy(maximum_attempts=2),
                        )

                        if task_id:
                            await adk.messages.create(
                                task_id=task_id,
                                content=TextContent(
                                    author="agent",
                                    content=f"""### 🔔 Attack Surface Changes Detected

| Change Type | Count |
|-------------|-------|
| New Assets | {len(new_assets)} |
| New Services | {len(new_services)} |
| Removed Assets | {len(changes.get('removed_domains', []))} |

*Alert sent to configured channels.*""",
                                ),
                                trace_id=task_id,
                            )

                # ===== SEND EXPOSURE ALERT FOR NEW DISCOVERIES =====
                # Alert on significant new discoveries (subdomains, services, APIs)
                if len(state_machine_data.discovered_assets) > 5:
                    try:
                        # Count new subdomains
                        new_subdomains = [
                            a.hostname for a in state_machine_data.discovered_assets
                            if a.hostname and '.' in a.hostname
                        ]

                        if new_subdomains:
                            await workflow.execute_activity(
                                send_exposure_alert_activity,
                                args=[
                                    organization_id,
                                    "subdomain",
                                    {"subdomains": new_subdomains[:20]},
                                    "medium" if len(new_subdomains) < 10 else "high",
                                    task_id,
                                    task_id,
                                ],
                                start_to_close_timeout=timedelta(seconds=30),
                                retry_policy=RetryPolicy(maximum_attempts=1),
                            )
                            logger.info(f"Sent exposure alert for {len(new_subdomains)} subdomains")

                        # Alert on new services
                        if all_services:
                            await workflow.execute_activity(
                                send_exposure_alert_activity,
                                args=[
                                    organization_id,
                                    "service",
                                    {"services": [f"{s['host']}:{s['port']} ({s['service']})" for s in all_services[:20]]},
                                    "medium",
                                    task_id,
                                    task_id,
                                ],
                                start_to_close_timeout=timedelta(seconds=30),
                                retry_policy=RetryPolicy(maximum_attempts=1),
                            )
                            logger.info(f"Sent exposure alert for {len(all_services)} services")

                        # Alert on new API endpoints
                        if api_endpoints:
                            await workflow.execute_activity(
                                send_exposure_alert_activity,
                                args=[
                                    organization_id,
                                    "api",
                                    {"apis": api_endpoints[:20]},
                                    "high" if len(api_endpoints) > 10 else "medium",
                                    task_id,
                                    task_id,
                                ],
                                start_to_close_timeout=timedelta(seconds=30),
                                retry_policy=RetryPolicy(maximum_attempts=1),
                            )
                            logger.info(f"Sent exposure alert for {len(api_endpoints)} API endpoints")

                    except Exception as e:
                        logger.warning(f"Failed to send exposure alerts: {e}")

                logger.info(f"Attack surface snapshot saved. Changes detected: {has_changes}")

            except Exception as e:
                logger.warning(f"Failed to save attack surface snapshot: {e}")

            logger.info(f"Attack surface mapped: {total_services_found} services found")
            # Now that we have technologies detected, gather threat intel
            return MajorProjectState.GATHERING_THREAT_INTEL

        except Exception as e:
            logger.error(f"Attack surface mapping failed: {e}")
            state_machine_data.error_message = f"Attack surface mapping failed: {str(e)}"

            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"**Error during attack surface mapping:** {str(e)}",
                    ),
                    trace_id=task_id,
                )

            return MajorProjectState.FAILED
