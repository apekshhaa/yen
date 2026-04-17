"""Attack Surface Agent for Major-Project pentesting."""
from __future__ import annotations

from datetime import timedelta
from typing import List, Optional

from openai_agents import Agent, function_tool
from temporalio import workflow
from temporalio.common import RetryPolicy

from project.activities.scanning_activities import (
    run_nmap_scan_activity,
    run_httpx_probe_activity,
    run_technology_detection_activity,
)
from project.constants import OPENAI_MODEL


@function_tool
async def run_nmap_scan(
    target: str,
    ports: str,
    scan_type: str,
    task_id: str,
) -> str:
    """
    Run Nmap port scan to identify open ports and services.

    Call this when:
    - You need to discover open ports on a target
    - Identifying running services
    - Fingerprinting service versions

    Args:
        target: Target IP or hostname
        ports: Port specification (e.g., "1-1000", "80,443,8080", or "top-1000")
        scan_type: Scan type ("quick", "full", "stealth", "aggressive")
        task_id: Task ID for tracing

    Returns:
        JSON string with discovered services and ports
    """
    retry_policy = RetryPolicy(
        initial_interval=timedelta(seconds=1),
        backoff_coefficient=2.0,
        maximum_interval=timedelta(seconds=120),
        maximum_attempts=3,
    )

    # Map scan types to nmap options
    scan_options = {
        "quick": "-sV -T4",
        "full": "-sV -sC -T4",
        "stealth": "-sS -sV -T2",
        "aggressive": "-A -T4",
    }

    options = scan_options.get(scan_type, "-sV -T4")

    try:
        result = await workflow.execute_activity(
            run_nmap_scan_activity,
            args=[target, ports, options, task_id, task_id],
            start_to_close_timeout=timedelta(minutes=30),
            schedule_to_close_timeout=timedelta(minutes=35),
            retry_policy=retry_policy,
        )

        import json
        return json.dumps(result)

    except Exception as e:
        workflow.logger.error(f"Nmap scan failed for {target}: {e}")
        return f"Error: Unable to scan {target}. {str(e)}"


@function_tool
async def probe_web_services(hosts: List[str], task_id: str) -> str:
    """
    Probe HTTP/HTTPS services using httpx to identify web applications.

    Call this when:
    - You've discovered hosts with web ports open
    - Need to identify web technologies
    - Mapping web application attack surface

    Args:
        hosts: List of hosts to probe (can include ports, e.g., "example.com:8080")
        task_id: Task ID for tracing

    Returns:
        JSON string with web service details
    """
    retry_policy = RetryPolicy(
        initial_interval=timedelta(seconds=1),
        backoff_coefficient=2.0,
        maximum_interval=timedelta(seconds=120),
        maximum_attempts=3,
    )

    try:
        result = await workflow.execute_activity(
            run_httpx_probe_activity,
            args=[hosts, task_id, task_id],
            start_to_close_timeout=timedelta(minutes=10),
            schedule_to_close_timeout=timedelta(minutes=15),
            retry_policy=retry_policy,
        )

        import json
        return json.dumps(result)

    except Exception as e:
        workflow.logger.error(f"HTTP probe failed: {e}")
        return f"Error: Unable to probe web services. {str(e)}"


@function_tool
async def detect_technologies(hosts: List[str], task_id: str) -> str:
    """
    Detect web technologies, frameworks, and CMS platforms.

    Call this when:
    - You've identified web applications
    - Need to fingerprint technologies
    - Building technology inventory for vulnerability correlation

    Args:
        hosts: List of web hosts to analyze
        task_id: Task ID for tracing

    Returns:
        JSON string with detected technologies
    """
    retry_policy = RetryPolicy(
        initial_interval=timedelta(seconds=1),
        backoff_coefficient=2.0,
        maximum_interval=timedelta(seconds=120),
        maximum_attempts=3,
    )

    try:
        result = await workflow.execute_activity(
            run_technology_detection_activity,
            args=[hosts, task_id, task_id],
            start_to_close_timeout=timedelta(minutes=10),
            schedule_to_close_timeout=timedelta(minutes=15),
            retry_policy=retry_policy,
        )

        import json
        return json.dumps(result)

    except Exception as e:
        workflow.logger.error(f"Technology detection failed: {e}")
        return f"Error: Unable to detect technologies. {str(e)}"


@function_tool
async def identify_attack_vectors(services_data: str, task_id: str) -> str:
    """
    Analyze discovered services to identify potential attack vectors.

    Call this when:
    - You have service scan results
    - Need to prioritize attack paths
    - Identifying entry points for exploitation

    Args:
        services_data: JSON string of discovered services
        task_id: Task ID for tracing

    Returns:
        JSON string with identified attack vectors and recommendations
    """
    import json

    workflow.logger.info("Analyzing services for attack vectors")

    try:
        services = json.loads(services_data)
    except json.JSONDecodeError:
        return json.dumps({
            "error": "Invalid services data format",
            "attack_vectors": [],
        })

    # Analyze services for common attack vectors
    attack_vectors = []

    # Check for common vulnerable services
    vulnerable_services = {
        "ssh": ["Brute force", "Key-based authentication bypass"],
        "ftp": ["Anonymous login", "Directory traversal"],
        "http": ["Web application vulnerabilities", "Directory enumeration"],
        "https": ["SSL/TLS vulnerabilities", "Web application vulnerabilities"],
        "mysql": ["SQL injection", "Weak credentials"],
        "postgresql": ["SQL injection", "Privilege escalation"],
        "smb": ["EternalBlue", "SMB relay attacks"],
        "rdp": ["BlueKeep", "Credential stuffing"],
    }

    if isinstance(services, dict) and "services" in services:
        for service in services.get("services", []):
            service_name = service.get("service", "").lower()
            port = service.get("port")

            if service_name in vulnerable_services:
                attack_vectors.append({
                    "service": service_name,
                    "port": port,
                    "vectors": vulnerable_services[service_name],
                    "priority": "high" if service_name in ["http", "https", "ssh"] else "medium",
                })

    result = {
        "total_vectors": len(attack_vectors),
        "attack_vectors": attack_vectors,
        "recommendations": [
            "Prioritize web services (HTTP/HTTPS) for vulnerability scanning",
            "Test SSH for weak credentials and key-based auth",
            "Enumerate web directories and endpoints",
        ],
    }

    return json.dumps(result)


def new_attack_surface_agent(
    discovered_assets: Optional[List[dict]] = None,
    task_id: str = "",
) -> Agent:
    """
    Create an Attack Surface Agent for service enumeration and mapping.

    This agent specializes in:
    - Port scanning with Nmap
    - Service version detection
    - Web application probing
    - Technology fingerprinting
    - Attack vector identification

    Args:
        discovered_assets: List of assets discovered during reconnaissance
        task_id: Task ID for tracing

    Returns:
        Agent configured for attack surface mapping
    """
    assets_str = "None discovered yet"
    if discovered_assets:
        assets_str = "\n".join([
            f"- {asset.get('hostname', asset.get('ip', 'Unknown'))}"
            for asset in discovered_assets[:20]  # Limit to first 20
        ])

    instructions = f"""
You are an Attack Surface Agent specializing in service enumeration and attack vector identification.

Your mission is to map the complete attack surface of discovered assets:
- Identify all open ports and running services
- Fingerprint service versions and technologies
- Probe web applications for frameworks and CMS
- Identify potential attack vectors and entry points

## Discovered Assets

{assets_str}

## Your Approach

1. **Port Scanning**: Use Nmap to discover open ports and services on each asset
   - Start with quick scans of common ports
   - Follow up with full scans on interesting targets
   - Use stealth scans when required

2. **Service Fingerprinting**: Identify exact versions of running services
   - Focus on web servers, databases, and remote access services
   - Note any outdated or EOL software

3. **Web Application Probing**: For web services, use httpx to:
   - Identify web servers and technologies
   - Detect CMS platforms (WordPress, Drupal, etc.)
   - Find interesting endpoints and directories

4. **Technology Detection**: Fingerprint web technologies
   - JavaScript frameworks
   - Server-side languages
   - Database systems
   - Cloud platforms

5. **Attack Vector Analysis**: Identify potential entry points
   - Prioritize by exploitability and impact
   - Consider authentication mechanisms
   - Note interesting configurations

## Tools Available

- `run_nmap_scan`: Scan ports and identify services
- `probe_web_services`: Probe HTTP/HTTPS services
- `detect_technologies`: Fingerprint web technologies
- `identify_attack_vectors`: Analyze services for attack paths

## Scan Strategy

- **Quick Scan**: Top 1000 ports, fast timing
- **Full Scan**: All 65535 ports, comprehensive
- **Stealth Scan**: SYN scan, slow timing for evasion
- **Aggressive Scan**: OS detection, version detection, scripts

## Important Guidelines

- Start with quick scans to get initial results fast
- Focus on web-facing services (ports 80, 443, 8080, 8443)
- Identify authentication mechanisms (SSH keys, basic auth, etc.)
- Note any unusual ports or services
- Document everything for the vulnerability reasoner

## Output Format

Provide a comprehensive attack surface map:
- Total open ports discovered
- Services by category (web, database, remote access, etc.)
- Technologies and versions identified
- Prioritized attack vectors
- Recommended next steps for vulnerability assessment

Remember: A complete attack surface map is critical for successful penetration testing!
"""

    return Agent(
        name="Attack Surface Agent",
        instructions=instructions,
        model=OPENAI_MODEL,
        tools=[
            run_nmap_scan,
            probe_web_services,
            detect_technologies,
            identify_attack_vectors,
        ],
    )