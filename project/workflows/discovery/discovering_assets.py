"""Discovering assets workflow state."""
from __future__ import annotations

from datetime import timedelta
from typing import Optional, override
import uuid

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
    DiscoveredAsset,
)

logger = make_logger(__name__)

# Import activities with workflow.unsafe context
with workflow.unsafe.imports_passed_through():
    from project.activities.discovery_activities import (
        run_subfinder_activity,
        run_asset_discovery_activity,
        resolve_dns_activity,
    )


class DiscoveringAssetsWorkflow(StateWorkflow):
    """Workflow for discovering assets using reconnaissance tools."""

    @override
    async def execute(
        self,
        state_machine: StateMachine,
        state_machine_data: Optional[MajorProjectData] = None,
    ) -> str:
        """
        Discover assets using subfinder, DNS resolution, and other recon tools.
        """
        if state_machine_data is None:
            return MajorProjectState.FAILED

        if state_machine_data.target_scope is None:
            state_machine_data.error_message = "No target scope configured"
            return MajorProjectState.FAILED

        logger.info("Starting asset discovery phase...")
        task_id = state_machine_data.task_id

        try:
            # Process each domain in scope
            for domain in state_machine_data.target_scope.domains:
                # Skip wildcard patterns for direct scanning
                if domain.startswith("*."):
                    base_domain = domain[2:]
                else:
                    base_domain = domain

                # Parse port from domain if present (e.g., "example.com:8080")
                explicit_port = None
                if ":" in base_domain and not base_domain.startswith("["):
                    # Handle host:port format (not IPv6)
                    parts = base_domain.rsplit(":", 1)
                    if parts[1].isdigit():
                        base_domain = parts[0]
                        explicit_port = int(parts[1])
                        logger.info(f"Parsed domain {domain} -> host={base_domain}, port={explicit_port}")

                # Check if this is an internal/private domain (K8s, local, etc.)
                # Subfinder won't work for these - skip subdomain enumeration
                is_internal_domain = any(
                    base_domain.endswith(suffix) for suffix in [
                        ".local", ".internal", ".svc.cluster.local", ".cluster.local",
                        ".localhost", ".test", ".example", ".invalid"
                    ]
                ) or base_domain.startswith("10.") or base_domain.startswith("192.168.")

                subdomains = []
                if not is_internal_domain:
                    # Run subfinder for subdomain enumeration (only for public domains)
                    logger.info(f"Running subfinder for domain: {base_domain}")

                    subfinder_result = await workflow.execute_activity(
                        run_subfinder_activity,
                        args=[base_domain, task_id, task_id],
                        start_to_close_timeout=timedelta(seconds=120),
                        retry_policy=RetryPolicy(
                            maximum_attempts=2,
                            initial_interval=timedelta(seconds=5),
                        ),
                    )

                    subdomains = subfinder_result.get("subdomains", [])
                    logger.info(f"Subfinder found {len(subdomains)} subdomains")
                else:
                    logger.info(f"Skipping subfinder for internal domain: {base_domain}")

                # Create asset for main domain
                main_asset = DiscoveredAsset(
                    id=str(uuid.uuid4()),
                    hostname=base_domain,
                )
                # If explicit port was provided, pre-populate ports
                if explicit_port:
                    main_asset.ports = [explicit_port]
                state_machine_data.discovered_assets.append(main_asset)

                # Add discovered subdomains as assets
                for subdomain in subdomains[:50]:  # Limit to 50 subdomains
                    # Check if not in excluded hosts
                    if subdomain not in state_machine_data.target_scope.excluded_hosts:
                        asset = DiscoveredAsset(
                            id=str(uuid.uuid4()),
                            hostname=subdomain,
                        )
                        state_machine_data.discovered_assets.append(asset)

                # DNS Resolution
                logger.info(f"Resolving DNS for {len(state_machine_data.discovered_assets)} assets")

                # Resolve DNS for discovered assets
                hosts_to_resolve = [a.hostname for a in state_machine_data.discovered_assets if not a.ip_address]
                dns_result = await workflow.execute_activity(
                    resolve_dns_activity,
                    args=[hosts_to_resolve, task_id, task_id],
                    start_to_close_timeout=timedelta(seconds=60),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )

                # Update assets with resolved IPs
                resolved_count = 0
                for hostname, ip in dns_result.get("resolved", {}).items():
                    for asset in state_machine_data.discovered_assets:
                        if asset.hostname == hostname:
                            asset.ip_address = ip
                            resolved_count += 1
                            break

                logger.info(f"DNS resolution complete: {resolved_count} hosts resolved")

            # Process IP ranges
            for ip_range in state_machine_data.target_scope.ip_ranges:
                logger.info(f"Discovering assets in IP range: {ip_range}")

                # Discover hosts in IP range
                range_result = await workflow.execute_activity(
                    run_asset_discovery_activity,
                    args=[ip_range, task_id, task_id],
                    start_to_close_timeout=timedelta(seconds=180),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )

                for host in range_result.get("hosts", []):
                    asset = DiscoveredAsset(
                        id=str(uuid.uuid4()),
                        hostname=host.get("hostname", host.get("ip")),
                        ip_address=host.get("ip"),
                    )
                    state_machine_data.discovered_assets.append(asset)

                logger.info(f"Asset discovery complete: {len(range_result.get('hosts', []))} hosts found")

            # Update statistics
            state_machine_data.stats["assets_discovered"] = len(state_machine_data.discovered_assets)

            # Build asset list for display
            assets_display = []
            for i, asset in enumerate(state_machine_data.discovered_assets[:50], 1):  # Show first 50
                ip_info = f" ({asset.ip_address})" if asset.ip_address else ""
                ports_info = f" - Ports: {', '.join(map(str, asset.ports))}" if asset.ports else ""
                assets_display.append(f"{i}. `{asset.hostname}`{ip_info}{ports_info}")

            # Group by domain for better organization
            domains_summary = {}
            for asset in state_machine_data.discovered_assets:
                # Extract root domain
                parts = asset.hostname.split('.')
                if len(parts) >= 2:
                    root_domain = '.'.join(parts[-2:])
                else:
                    root_domain = asset.hostname

                if root_domain not in domains_summary:
                    domains_summary[root_domain] = []
                domains_summary[root_domain].append(asset.hostname)

            # Build domain summary
            domain_summary_lines = []
            for domain, hosts in domains_summary.items():
                domain_summary_lines.append(f"- **{domain}**: {len(hosts)} asset(s)")

            # Send detailed summary
            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"""## 🔍 Asset Discovery Complete

### Summary
| Metric | Count |
|--------|-------|
| **Total Assets Discovered** | {len(state_machine_data.discovered_assets)} |
| **Domains Scanned** | {len(state_machine_data.target_scope.domains)} |
| **IP Ranges Scanned** | {len(state_machine_data.target_scope.ip_ranges)} |

### Domains Overview
{chr(10).join(domain_summary_lines) if domain_summary_lines else "No domains found"}

### Discovered Assets
{chr(10).join(assets_display) if assets_display else "No assets discovered"}
{f'{chr(10)}*...and {len(state_machine_data.discovered_assets) - 50} more assets*' if len(state_machine_data.discovered_assets) > 50 else ''}

---
*Moving to attack surface mapping...*""",
                    ),
                    trace_id=task_id,
                )

            logger.info(f"Asset discovery complete: {len(state_machine_data.discovered_assets)} assets found")
            # Go directly to attack surface mapping - we'll gather threat intel AFTER tech detection
            return MajorProjectState.MAPPING_ATTACK_SURFACE

        except Exception as e:
            logger.error(f"Asset discovery failed: {e}")
            state_machine_data.error_message = f"Asset discovery failed: {str(e)}"

            if task_id:
                await adk.messages.create(
                    task_id=task_id,
                    content=TextContent(
                        author="agent",
                        content=f"**Error during asset discovery:** {str(e)}",
                    ),
                    trace_id=task_id,
                )

            return MajorProjectState.FAILED
