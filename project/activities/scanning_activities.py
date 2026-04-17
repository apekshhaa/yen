"""Scanning activities for Major-Project agent - Production Ready with Real Scanners."""
import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from temporalio import activity

from agentex.lib.utils.logging import make_logger

logger = make_logger(__name__)


@activity.defn(name="run_nmap_scan_activity")
async def run_nmap_scan_activity(
    target: str, ports: str, options: str, task_id: str, trace_id: str
) -> Dict[str, Any]:
    """
    Run actual nmap port scan on target.

    Args:
        target: Target IP or hostname
        ports: Port specification (e.g., "1-1000" or "80,443")
        options: Nmap options
        task_id: Task ID for tracing
        trace_id: Trace ID for logging

    Returns:
        Dictionary with scan results
    """
    logger.info(f"Running nmap scan on {target} ports {ports}")

    try:
        # Build nmap command
        cmd = [
            "nmap",
            "-p", ports,
            "-sV",  # Service version detection
            "-sC",  # Default scripts
            "--open",  # Only show open ports
            "-oX", "-",  # XML output to stdout
            target
        ]

        if options:
            cmd.extend(options.split())

        # Run nmap
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            logger.error(f"Nmap failed: {stderr.decode()}")
            return {
                "target": target,
                "ports_scanned": 0,
                "services": [],
                "open_ports": 0,
                "error": stderr.decode(),
            }

        # Parse XML output
        import xml.etree.ElementTree as ET
        root = ET.fromstring(stdout.decode())

        services = []
        for host in root.findall('.//host'):
            for port in host.findall('.//port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                state = port.find('state').get('state')

                service_elem = port.find('service')
                service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                service_version = service_elem.get('version', '') if service_elem is not None else ''

                if state == 'open':
                    services.append({
                        "port": int(port_id),
                        "protocol": protocol,
                        "state": state,
                        "service": service_name,
                        "version": service_version,
                    })

        result = {
            "target": target,
            "ports_scanned": len(ports.split(',')) if ',' in ports else 1000,
            "services": services,
            "open_ports": len(services),
        }

        logger.info(f"Nmap scan completed: {len(services)} open ports found on {target}")
        return result

    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")
        return {
            "target": target,
            "ports_scanned": 0,
            "services": [],
            "open_ports": 0,
            "error": str(e),
        }


@activity.defn(name="run_nuclei_scan_activity")
async def run_nuclei_scan_activity(
    targets: List[str], templates: str, task_id: str, trace_id: str
) -> Dict[str, Any]:
    """
    Run actual nuclei vulnerability scanner.

    Args:
        targets: List of target URLs
        templates: Template category - "web" for HTTP templates, "dast" for DAST, or specific tags
        task_id: Task ID for tracing
        trace_id: Trace ID for logging

    Returns:
        Dictionary with vulnerability findings
    """
    logger.info(f"Running nuclei scan on {len(targets)} targets with templates: {templates}")

    try:
        # Create temporary file for targets
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write('\n'.join(targets))
            targets_file = f.name

        # Create temporary file for output
        output_file = tempfile.mktemp(suffix='.json')

        # Find nuclei templates directory - check common locations
        template_paths = []
        possible_template_dirs = [
            "/root/nuclei-templates",
            "/root/.local/nuclei-templates",
            "/home/nuclei-templates",
            Path.home() / "nuclei-templates",
            Path.home() / ".local" / "nuclei-templates",
        ]

        base_template_dir = None
        for base_dir in possible_template_dirs:
            base_path = Path(base_dir)
            if base_path.exists():
                base_template_dir = base_path
                # Use targeted template subdirectories to reduce memory usage
                # Focus on the most relevant web vulnerability templates
                priority_subdirs = [
                    "http/cves",           # Known CVEs
                    "http/vulnerabilities", # General vulnerabilities
                    "http/exposures",       # Exposed data/configs
                    "http/misconfiguration", # Misconfigurations
                    "http/technologies",    # Tech detection (fast)
                ]
                for subdir in priority_subdirs:
                    subpath = base_path / subdir
                    if subpath.exists():
                        template_paths.append(str(subpath))
                break

        if not template_paths:
            logger.warning("No nuclei templates found in expected locations, using default templates")
        else:
            logger.info(f"Using {len(template_paths)} template directories from {base_template_dir}")

        # Build nuclei command
        cmd = [
            "nuclei",
            "-l", targets_file,
        ]

        # Add template paths if found, otherwise use nuclei's default templates
        if template_paths:
            for tpath in template_paths:
                cmd.extend(["-t", tpath])
        # else: nuclei will use its default templates automatically

        cmd.extend([
            "-severity", "critical,high,medium,low,info",  # Include info for more findings
            "-json",
            "-o", output_file,
            "-rate-limit", "150",  # Respectful rate limiting
            "-timeout", "15",  # 15 second timeout per request
            "-retries", "2",
            "-nc",  # No color for cleaner logs
        ])

        logger.info(f"Nuclei command: {' '.join(cmd)}")
        logger.info(f"Scanning targets: {targets[:5]}{'...' if len(targets) > 5 else ''}")

        # Run nuclei
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if stderr:
            stderr_text = stderr.decode()
            if stderr_text.strip():
                logger.warning(f"Nuclei stderr: {stderr_text[:500]}")

        if process.returncode != 0:
            logger.warning(f"Nuclei exited with code {process.returncode}")

        # Parse results
        vulnerabilities = []
        if Path(output_file).exists():
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            result = json.loads(line)
                            vuln = {
                                "name": result.get('info', {}).get('name', 'Unknown'),
                                "severity": result.get('info', {}).get('severity', 'info'),
                                "cvss_score": result.get('info', {}).get('classification', {}).get('cvss-score'),
                                "host": result.get('host', ''),
                                "matched_at": result.get('matched-at', ''),
                                "description": result.get('info', {}).get('description', ''),
                                "evidence": result.get('matched-at', ''),
                                "template_id": result.get('template-id', ''),
                                "cve_ids": result.get('info', {}).get('classification', {}).get('cve-id', []),
                            }
                            vulnerabilities.append(vuln)
                        except json.JSONDecodeError:
                            continue

        # Cleanup
        Path(targets_file).unlink(missing_ok=True)
        Path(output_file).unlink(missing_ok=True)

        result = {
            "targets": targets,
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities),
        }

        logger.info(f"Nuclei scan completed: {len(vulnerabilities)} vulnerabilities found")
        return result

    except Exception as e:
        logger.error(f"Nuclei scan failed: {e}")
        return {
            "targets": targets,
            "vulnerabilities": [],
            "count": 0,
            "error": str(e),
        }


@activity.defn(name="run_httpx_probe_activity")
async def run_httpx_probe_activity(
    hosts: List[str], task_id: str, trace_id: str
) -> Dict[str, Any]:
    """
    Probe HTTP/HTTPS services using actual httpx tool.

    Args:
        hosts: List of hosts to probe
        task_id: Task ID for tracing
        trace_id: Trace ID for logging

    Returns:
        Dictionary with HTTP probe results
    """
    logger.info(f"Running httpx probe on {len(hosts)} hosts")

    try:
        # Create temporary file for hosts
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write('\n'.join(hosts[:100]))  # Limit to 100
            hosts_file = f.name

        # Build httpx command
        cmd = [
            "httpx",
            "-l", hosts_file,
            "-json",
            "-silent",
            "-status-code",
            "-tech-detect",
            "-server",
            "-title",
            "-rate-limit", "100",
        ]

        # Run httpx
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        # Parse results
        probes = []
        for line in stdout.decode().split('\n'):
            if line.strip():
                try:
                    result = json.loads(line)
                    probe = {
                        "host": result.get('host', ''),
                        "url": result.get('url', ''),
                        "status_code": result.get('status_code', 0),
                        "server": result.get('webserver', ''),
                        "title": result.get('title', ''),
                        "technologies": result.get('tech', []),
                        "content_length": result.get('content_length', 0),
                    }
                    probes.append(probe)
                except json.JSONDecodeError:
                    continue

        # Cleanup
        Path(hosts_file).unlink(missing_ok=True)

        result = {
            "probes": probes,
            "count": len(probes),
        }

        logger.info(f"Httpx probe completed: {len(probes)} web servers found")
        return result

    except Exception as e:
        logger.error(f"Httpx probe failed: {e}")
        return {
            "probes": [],
            "count": 0,
            "error": str(e),
        }


@activity.defn(name="run_technology_detection_activity")
async def run_technology_detection_activity(
    hosts: List[str], task_id: str, trace_id: str
) -> Dict[str, Any]:
    """
    Detect technologies using httpx tech detection.

    Args:
        hosts: List of hosts to analyze
        task_id: Task ID for tracing
        trace_id: Trace ID for logging

    Returns:
        Dictionary with detected technologies
    """
    logger.info(f"Running technology detection on {len(hosts)} hosts")

    try:
        # Use httpx for technology detection
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write('\n'.join(hosts[:100]))
            hosts_file = f.name

        cmd = [
            "httpx",
            "-l", hosts_file,
            "-json",
            "-silent",
            "-tech-detect",
            "-rate-limit", "100",
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        detections = []
        for line in stdout.decode().split('\n'):
            if line.strip():
                try:
                    result = json.loads(line)
                    detection = {
                        "host": result.get('host', ''),
                        "technologies": result.get('tech', []),
                        "server": result.get('webserver', ''),
                    }
                    detections.append(detection)
                except json.JSONDecodeError:
                    continue

        Path(hosts_file).unlink(missing_ok=True)

        result = {
            "detections": detections,
            "count": len(detections),
        }

        logger.info(f"Technology detection completed: {len(detections)} hosts analyzed")
        return result

    except Exception as e:
        logger.error(f"Technology detection failed: {e}")
        return {
            "detections": [],
            "count": 0,
            "error": str(e),
        }