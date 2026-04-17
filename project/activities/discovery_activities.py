"""Discovery activities for Major-Project agent - Production Ready with Real Tools."""
import asyncio
import json
import socket
import subprocess
from typing import Any, Dict, List

from temporalio import activity

from agentex.lib.utils.logging import make_logger

logger = make_logger(__name__)


@activity.defn(name="run_subfinder_activity")
async def run_subfinder_activity(domain: str, task_id: str, trace_id: str) -> Dict[str, Any]:
    """
    Run actual subfinder to discover subdomains.

    Args:
        domain: Target domain to enumerate
        task_id: Task ID for tracing
        trace_id: Trace ID for logging

    Returns:
        Dictionary with discovered subdomains
    """
    logger.info(f"Running subfinder for domain: {domain}")

    try:
        # Run actual subfinder
        cmd = [
            "subfinder",
            "-d", domain,
            "-silent",
            "-json",
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        subdomains = []
        for line in stdout.decode().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    subdomain = data.get('host', '')
                    if subdomain:
                        subdomains.append(subdomain)
                except json.JSONDecodeError:
                    # If not JSON, treat as plain subdomain
                    if line.strip():
                        subdomains.append(line.strip())

        result = {
            "domain": domain,
            "subdomains": subdomains,
            "count": len(subdomains),
        }

        logger.info(f"Subfinder found {len(subdomains)} subdomains for {domain}")
        return result

    except Exception as e:
        logger.error(f"Subfinder failed: {e}")
        return {
            "domain": domain,
            "subdomains": [],
            "count": 0,
            "error": str(e),
        }


@activity.defn(name="run_asset_discovery_activity")
async def run_asset_discovery_activity(
    ip_range: str, task_id: str, trace_id: str
) -> Dict[str, Any]:
    """
    Discover live hosts in an IP range using nmap ping scan.

    Args:
        ip_range: IP range to scan (CIDR notation)
        task_id: Task ID for tracing
        trace_id: Trace ID for logging

    Returns:
        Dictionary with discovered hosts
    """
    logger.info(f"Running asset discovery for IP range: {ip_range}")

    try:
        # Use nmap for host discovery
        cmd = [
            "nmap",
            "-sn",  # Ping scan (no port scan)
            "-oX", "-",  # XML output to stdout
            ip_range
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        # Parse XML output
        import xml.etree.ElementTree as ET
        root = ET.fromstring(stdout.decode())

        hosts = []
        for host in root.findall('.//host'):
            status = host.find('status')
            if status is not None and status.get('state') == 'up':
                address = host.find('address')
                hostname_elem = host.find('.//hostname')

                ip = address.get('addr') if address is not None else ''
                hostname = hostname_elem.get('name') if hostname_elem is not None else ''

                hosts.append({
                    "ip": ip,
                    "hostname": hostname or ip,
                })

        result = {
            "ip_range": ip_range,
            "hosts": hosts,
            "count": len(hosts),
        }

        logger.info(f"Asset discovery found {len(hosts)} hosts in {ip_range}")
        return result

    except Exception as e:
        logger.error(f"Asset discovery failed: {e}")
        return {
            "ip_range": ip_range,
            "hosts": [],
            "count": 0,
            "error": str(e),
        }


@activity.defn(name="resolve_dns_activity")
async def resolve_dns_activity(
    hostnames: List[str], task_id: str, trace_id: str
) -> Dict[str, Any]:
    """
    Resolve DNS for a list of hostnames using actual DNS lookups.

    Args:
        hostnames: List of hostnames to resolve
        task_id: Task ID for tracing
        trace_id: Trace ID for logging

    Returns:
        Dictionary with resolved IPs
    """
    logger.info(f"Resolving DNS for {len(hostnames)} hostnames")

    try:
        resolved = {}

        # Use actual DNS resolution
        for hostname in hostnames[:100]:  # Limit to 100
            try:
                # Run in executor to avoid blocking
                loop = asyncio.get_event_loop()
                ip = await loop.run_in_executor(
                    None,
                    socket.gethostbyname,
                    hostname
                )
                resolved[hostname] = ip
            except socket.gaierror:
                # DNS resolution failed for this hostname
                logger.debug(f"Failed to resolve {hostname}")
                continue
            except Exception as e:
                logger.debug(f"Error resolving {hostname}: {e}")
                continue

        result = {
            "resolved": resolved,
            "count": len(resolved),
        }

        logger.info(f"DNS resolution completed: {len(resolved)} hosts resolved")
        return result

    except Exception as e:
        logger.error(f"DNS resolution failed: {e}")
        return {
            "resolved": {},
            "count": 0,
            "error": str(e),
        }