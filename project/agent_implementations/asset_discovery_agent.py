"""Asset Discovery Agent for Major-Project pentesting."""
from __future__ import annotations

from datetime import timedelta
from typing import List, Optional

from openai_agents import Agent, function_tool
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.contrib import openai_agents

from project.activities.discovery_activities import (
    run_subfinder_activity,
    run_asset_discovery_activity,
    resolve_dns_activity,
)
from project.constants import OPENAI_MODEL


@function_tool
async def run_subfinder(domain: str, task_id: str) -> str:
    """
    Discover subdomains for a target domain using subfinder.

    Call this when:
    - You need to enumerate all subdomains for a domain
    - Starting reconnaissance on a new target
    - Expanding the attack surface

    Args:
        domain: Target domain to enumerate (e.g., "example.com")
        task_id: Task ID for tracing

    Returns:
        JSON string with discovered subdomains
    """
    retry_policy = RetryPolicy(
        initial_interval=timedelta(seconds=1),
        backoff_coefficient=2.0,
        maximum_interval=timedelta(seconds=120),
        maximum_attempts=3,
    )

    try:
        result = await workflow.execute_activity(
            run_subfinder_activity,
            args=[domain, task_id, task_id],
            start_to_close_timeout=timedelta(minutes=10),
            schedule_to_close_timeout=timedelta(minutes=15),
            retry_policy=retry_policy,
        )

        import json
        return json.dumps(result)

    except Exception as e:
        workflow.logger.error(f"Subfinder failed for {domain}: {e}")
        return f"Error: Unable to run subfinder for {domain}. {str(e)}"


@function_tool
async def discover_assets(ip_range: str, task_id: str) -> str:
    """
    Discover live hosts in an IP range using network scanning.

    Call this when:
    - You have an IP range to scan
    - Need to identify active hosts
    - Mapping network infrastructure

    Args:
        ip_range: IP range in CIDR notation (e.g., "192.168.1.0/24")
        task_id: Task ID for tracing

    Returns:
        JSON string with discovered hosts
    """
    retry_policy = RetryPolicy(
        initial_interval=timedelta(seconds=1),
        backoff_coefficient=2.0,
        maximum_interval=timedelta(seconds=120),
        maximum_attempts=3,
    )

    try:
        result = await workflow.execute_activity(
            run_asset_discovery_activity,
            args=[ip_range, task_id, task_id],
            start_to_close_timeout=timedelta(minutes=15),
            schedule_to_close_timeout=timedelta(minutes=20),
            retry_policy=retry_policy,
        )

        import json
        return json.dumps(result)

    except Exception as e:
        workflow.logger.error(f"Asset discovery failed for {ip_range}: {e}")
        return f"Error: Unable to discover assets in {ip_range}. {str(e)}"


@function_tool
async def resolve_dns(hostnames: List[str], task_id: str) -> str:
    """
    Resolve DNS records for a list of hostnames to get IP addresses.

    Call this when:
    - You have discovered subdomains that need IP resolution
    - Need to map hostnames to IPs
    - Validating discovered assets

    Args:
        hostnames: List of hostnames to resolve
        task_id: Task ID for tracing

    Returns:
        JSON string with hostname to IP mappings
    """
    retry_policy = RetryPolicy(
        initial_interval=timedelta(seconds=1),
        backoff_coefficient=2.0,
        maximum_interval=timedelta(seconds=120),
        maximum_attempts=3,
    )

    try:
        result = await workflow.execute_activity(
            resolve_dns_activity,
            args=[hostnames, task_id, task_id],
            start_to_close_timeout=timedelta(minutes=5),
            schedule_to_close_timeout=timedelta(minutes=10),
            retry_policy=retry_policy,
        )

        import json
        return json.dumps(result)

    except Exception as e:
        workflow.logger.error(f"DNS resolution failed: {e}")
        return f"Error: Unable to resolve DNS for hostnames. {str(e)}"


def new_asset_discovery_agent(
    target_domains: Optional[List[str]] = None,
    target_ip_ranges: Optional[List[str]] = None,
    task_id: str = "",
) -> Agent:
    """
    Create an Asset Discovery Agent for reconnaissance.

    This agent specializes in:
    - Subdomain enumeration using subfinder
    - Network host discovery
    - DNS resolution and mapping
    - Building comprehensive asset inventory

    Args:
        target_domains: List of domains to enumerate
        target_ip_ranges: List of IP ranges to scan
        task_id: Task ID for tracing

    Returns:
        Agent configured for asset discovery
    """
    domains_str = ", ".join(target_domains) if target_domains else "None specified"
    ip_ranges_str = ", ".join(target_ip_ranges) if target_ip_ranges else "None specified"

    instructions = f"""
You are an Asset Discovery Agent specializing in reconnaissance for penetration testing.

Your mission is to discover and enumerate ALL assets within the authorized scope:
- Subdomains and DNS records
- Live hosts and IP addresses
- Network infrastructure
- Cloud assets and services

## Current Scope

Target Domains: {domains_str}
Target IP Ranges: {ip_ranges_str}

## Your Approach

1. **Subdomain Enumeration**: Use subfinder to discover all subdomains for each target domain
2. **DNS Resolution**: Resolve all discovered hostnames to IP addresses
3. **Network Discovery**: Scan IP ranges to identify live hosts
4. **Asset Cataloging**: Build a comprehensive inventory of discovered assets

## Tools Available

- `run_subfinder`: Discover subdomains for a domain
- `discover_assets`: Find live hosts in an IP range
- `resolve_dns`: Resolve hostnames to IP addresses

## Important Guidelines

- ALWAYS stay within the authorized scope
- Be thorough - discover ALL assets, not just obvious ones
- Document everything you find
- Look for patterns in naming conventions
- Identify cloud providers and services
- Note any interesting or unusual findings

## Output Format

Provide a structured summary of:
- Total subdomains discovered
- Total hosts identified
- IP address mappings
- Notable findings or patterns
- Recommended next steps for attack surface mapping

Remember: The goal is COMPLETE asset discovery within scope. Leave no stone unturned!
"""

    return Agent(
        name="Asset Discovery Agent",
        instructions=instructions,
        model=OPENAI_MODEL,
        tools=[
            run_subfinder,
            discover_assets,
            resolve_dns,
        ],
    )