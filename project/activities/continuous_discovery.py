"""
Continuous Attack Surface Discovery for Major-Project AI Pentester.

This module implements continuous monitoring and discovery of the attack surface,
enabling the agent to detect new assets, endpoints, and changes that could
indicate new vulnerabilities.

Key Features:
- Scheduled asset discovery with delta detection
- New endpoint monitoring
- Technology change detection
- Automatic re-scanning of changed assets
"""
import asyncio
import hashlib
import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from openai import AsyncOpenAI
from temporalio import activity

from agentex.lib.utils.logging import make_logger
from agentex.lib import adk
from agentex.types.text_content import TextContent

logger = make_logger(__name__)


class AttackSurfaceState:
    """Maintains state of the attack surface for delta detection."""

    def __init__(self):
        self.known_assets: Dict[str, Dict[str, Any]] = {}
        self.known_endpoints: Dict[str, Set[str]] = {}
        self.known_technologies: Dict[str, Set[str]] = {}
        self.asset_hashes: Dict[str, str] = {}
        self.last_scan_times: Dict[str, datetime] = {}
        self.change_history: List[Dict[str, Any]] = []

    def compute_asset_hash(self, asset: Dict[str, Any]) -> str:
        """Compute hash of asset state for change detection."""
        # Include key attributes that indicate changes
        hash_data = {
            "ports": sorted(asset.get("ports", [])),
            "services": sorted([str(s) for s in asset.get("services", [])]),
            "technologies": sorted(asset.get("technologies", [])),
        }
        return hashlib.sha256(json.dumps(hash_data, sort_keys=True).encode()).hexdigest()[:16]

    def detect_changes(self, asset_id: str, new_asset: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect changes in an asset compared to known state."""
        changes = []
        new_hash = self.compute_asset_hash(new_asset)

        if asset_id not in self.known_assets:
            changes.append({
                "type": "new_asset",
                "asset_id": asset_id,
                "details": new_asset,
                "timestamp": datetime.utcnow().isoformat(),
            })
        elif self.asset_hashes.get(asset_id) != new_hash:
            old_asset = self.known_assets[asset_id]

            # Detect new ports
            old_ports = set(old_asset.get("ports", []))
            new_ports = set(new_asset.get("ports", []))
            if new_ports - old_ports:
                changes.append({
                    "type": "new_ports",
                    "asset_id": asset_id,
                    "new_ports": list(new_ports - old_ports),
                    "timestamp": datetime.utcnow().isoformat(),
                })

            # Detect new technologies
            old_techs = set(old_asset.get("technologies", []))
            new_techs = set(new_asset.get("technologies", []))
            if new_techs - old_techs:
                changes.append({
                    "type": "new_technologies",
                    "asset_id": asset_id,
                    "new_technologies": list(new_techs - old_techs),
                    "timestamp": datetime.utcnow().isoformat(),
                })

            # Detect service changes
            old_services = set(str(s) for s in old_asset.get("services", []))
            new_services = set(str(s) for s in new_asset.get("services", []))
            if new_services - old_services:
                changes.append({
                    "type": "new_services",
                    "asset_id": asset_id,
                    "new_services": list(new_services - old_services),
                    "timestamp": datetime.utcnow().isoformat(),
                })

        # Update state
        self.known_assets[asset_id] = new_asset
        self.asset_hashes[asset_id] = new_hash
        self.last_scan_times[asset_id] = datetime.utcnow()
        self.change_history.extend(changes)

        return changes


# Global state (in production, this would be persisted)
_attack_surface_state = AttackSurfaceState()


async def call_llm_for_analysis(prompt: str, system_prompt: str) -> str:
    """Call LLM for attack surface analysis."""
    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    model = os.environ.get("OPENAI_MODEL", "gpt-4")

    if not api_key:
        raise ValueError("OPENAI_API_KEY not set")

    client = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=90.0,
    )

    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        temperature=0.7,
        max_tokens=2000,
    )

    return response.choices[0].message.content


@activity.defn(name="continuous_asset_discovery_activity")
async def continuous_asset_discovery_activity(
    domains: List[str],
    ip_ranges: List[str],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Continuously discover and monitor assets in the target scope.

    This activity:
    1. Discovers new subdomains and hosts
    2. Compares against known state
    3. Identifies changes that warrant re-scanning
    4. Prioritizes new/changed assets for vulnerability testing
    """
    logger.info(f"Running continuous asset discovery for {len(domains)} domains, {len(ip_ranges)} IP ranges")

    activity.heartbeat("Starting continuous asset discovery")

    discovered_assets = []
    changes_detected = []

    # Discover subdomains for each domain
    for domain in domains:
        try:
            activity.heartbeat(f"Discovering subdomains for {domain}")

            # Run subfinder
            cmd = ["subfinder", "-d", domain, "-silent", "-json"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()

            subdomains = []
            for line in stdout.decode().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        subdomain = data.get('host', '')
                        if subdomain:
                            subdomains.append(subdomain)
                    except json.JSONDecodeError:
                        if line.strip():
                            subdomains.append(line.strip())

            # Check each subdomain for changes
            for subdomain in subdomains:
                asset_id = subdomain
                asset_data = {
                    "hostname": subdomain,
                    "domain": domain,
                    "discovered_at": datetime.utcnow().isoformat(),
                    "ports": [],
                    "services": [],
                    "technologies": [],
                }

                # Quick port probe
                probe_cmd = ["nmap", "-p", "80,443,8080,8443", "-T4", "--open", "-oG", "-", subdomain]
                try:
                    probe_proc = await asyncio.create_subprocess_exec(
                        *probe_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    probe_stdout, _ = await asyncio.wait_for(probe_proc.communicate(), timeout=30)

                    # Parse open ports
                    import re
                    ports = re.findall(r'(\d+)/open', probe_stdout.decode())
                    asset_data["ports"] = [int(p) for p in ports]
                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    logger.debug(f"Port probe failed for {subdomain}: {e}")

                # Detect changes
                asset_changes = _attack_surface_state.detect_changes(asset_id, asset_data)
                if asset_changes:
                    changes_detected.extend(asset_changes)

                discovered_assets.append(asset_data)

        except Exception as e:
            logger.error(f"Asset discovery failed for {domain}: {e}")

    # Discover hosts in IP ranges
    for ip_range in ip_ranges:
        try:
            activity.heartbeat(f"Discovering hosts in {ip_range}")

            cmd = ["nmap", "-sn", "-oG", "-", ip_range]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()

            import re
            hosts = re.findall(r'Host: (\d+\.\d+\.\d+\.\d+)', stdout.decode())

            for host_ip in hosts:
                asset_id = host_ip
                asset_data = {
                    "ip_address": host_ip,
                    "ip_range": ip_range,
                    "discovered_at": datetime.utcnow().isoformat(),
                    "ports": [],
                    "services": [],
                    "technologies": [],
                }

                asset_changes = _attack_surface_state.detect_changes(asset_id, asset_data)
                if asset_changes:
                    changes_detected.extend(asset_changes)

                discovered_assets.append(asset_data)

        except Exception as e:
            logger.error(f"IP range discovery failed for {ip_range}: {e}")

    # Notify about changes
    if task_id and changes_detected:
        change_summary = "\n".join([
            f"- **{c['type']}**: {c.get('asset_id', 'unknown')} - {c.get('details', c.get('new_ports', c.get('new_technologies', '')))}"
            for c in changes_detected[:10]
        ])

        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🔄 Attack Surface Changes Detected

**New/Changed Assets:** {len(changes_detected)}

{change_summary}

These changes will be prioritized for vulnerability scanning.""",
            ),
            trace_id=trace_id,
        )

    return {
        "discovered_assets": discovered_assets,
        "total_assets": len(discovered_assets),
        "changes_detected": changes_detected,
        "change_count": len(changes_detected),
        "scan_timestamp": datetime.utcnow().isoformat(),
    }


@activity.defn(name="endpoint_change_detection_activity")
async def endpoint_change_detection_activity(
    target_url: str,
    known_endpoints: List[str],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Detect new endpoints and API changes on a target.

    This activity:
    1. Crawls the target for endpoints
    2. Compares against known endpoints
    3. Identifies new endpoints for testing
    4. Detects removed endpoints (potential security changes)
    """
    logger.info(f"Running endpoint change detection for {target_url}")

    activity.heartbeat("Crawling for endpoint changes")

    try:
        import tempfile

        # Use katana for crawling
        output_file = tempfile.mktemp(suffix='.json')
        cmd = [
            "katana",
            "-u", target_url,
            "-d", "3",
            "-jc",
            "-json",
            "-o", output_file,
            "-silent",
            "-timeout", "30",
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()

        current_endpoints = set()

        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            result = json.loads(line)
                            url = result.get('request', {}).get('endpoint', '')
                            if url:
                                current_endpoints.add(url)
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            pass

        # Compare with known endpoints
        known_set = set(known_endpoints)
        new_endpoints = current_endpoints - known_set
        removed_endpoints = known_set - current_endpoints

        # Analyze new endpoints for potential vulnerabilities
        new_endpoint_analysis = []
        if new_endpoints:
            for endpoint in list(new_endpoints)[:20]:
                analysis = {
                    "endpoint": endpoint,
                    "potential_vulns": [],
                }

                # Quick heuristic analysis
                endpoint_lower = endpoint.lower()
                if any(p in endpoint_lower for p in ['id=', 'user', 'account', 'profile']):
                    analysis["potential_vulns"].append("IDOR")
                if any(p in endpoint_lower for p in ['search', 'query', 'q=', 'filter']):
                    analysis["potential_vulns"].append("SQLi")
                if any(p in endpoint_lower for p in ['url=', 'redirect', 'callback', 'next']):
                    analysis["potential_vulns"].append("SSRF/Open Redirect")
                if any(p in endpoint_lower for p in ['file', 'path', 'document', 'download']):
                    analysis["potential_vulns"].append("Path Traversal")
                if any(p in endpoint_lower for p in ['api', 'rest', 'graphql']):
                    analysis["potential_vulns"].append("API Security")

                new_endpoint_analysis.append(analysis)

        # Notify about changes
        if task_id and (new_endpoints or removed_endpoints):
            new_list = "\n".join([f"  - `{e}`" for e in list(new_endpoints)[:10]])
            removed_list = "\n".join([f"  - `{e}`" for e in list(removed_endpoints)[:5]])

            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content=f"""### 🔍 Endpoint Changes Detected

**New Endpoints:** {len(new_endpoints)}
{new_list if new_endpoints else "  None"}

**Removed Endpoints:** {len(removed_endpoints)}
{removed_list if removed_endpoints else "  None"}

New endpoints will be prioritized for vulnerability testing.""",
                ),
                trace_id=trace_id,
            )

        return {
            "target_url": target_url,
            "current_endpoints": list(current_endpoints),
            "new_endpoints": list(new_endpoints),
            "removed_endpoints": list(removed_endpoints),
            "new_endpoint_analysis": new_endpoint_analysis,
            "total_current": len(current_endpoints),
            "total_new": len(new_endpoints),
            "total_removed": len(removed_endpoints),
        }

    except Exception as e:
        logger.error(f"Endpoint change detection failed: {e}")
        return {
            "target_url": target_url,
            "error": str(e),
            "current_endpoints": [],
            "new_endpoints": [],
            "removed_endpoints": [],
        }


@activity.defn(name="prioritize_scan_targets_activity")
async def prioritize_scan_targets_activity(
    changes: List[Dict[str, Any]],
    assets: List[Dict[str, Any]],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Use AI to prioritize which assets/endpoints to scan based on changes.

    This activity:
    1. Analyzes detected changes
    2. Considers asset criticality
    3. Prioritizes based on potential vulnerability impact
    4. Returns ordered list of scan targets
    """
    logger.info(f"Prioritizing {len(changes)} changes and {len(assets)} assets for scanning")

    if not changes and not assets:
        return {"prioritized_targets": [], "reasoning": "No targets to prioritize"}

    # Build context for LLM
    changes_summary = json.dumps(changes[:20], indent=2) if changes else "No recent changes"
    assets_summary = json.dumps(assets[:20], indent=2) if assets else "No assets"

    prompt = f"""Analyze these attack surface changes and assets to prioritize vulnerability scanning.

## Recent Changes
{changes_summary}

## Assets
{assets_summary}

## Task
Prioritize which assets/endpoints should be scanned first based on:
1. New assets/endpoints (highest priority - unknown security posture)
2. Changed assets (new ports, services, technologies)
3. Assets with high-risk indicators (admin panels, APIs, auth endpoints)
4. Assets with known vulnerable technologies

Return a JSON array of prioritized targets:
```json
[
  {{
    "target": "hostname or URL",
    "priority": 1-10,
    "reason": "Why this should be scanned",
    "recommended_tests": ["sqli", "xss", "ssrf", etc],
    "risk_indicators": ["list of risk factors"]
  }}
]
```

Focus on the top 10 highest priority targets."""

    system_prompt = """You are a security expert prioritizing penetration testing targets.
Focus on assets that are most likely to have vulnerabilities or highest impact if compromised.
Consider: new/changed assets, exposed services, sensitive endpoints, known vulnerable technologies."""

    try:
        activity.heartbeat("Analyzing targets with AI")

        response = await call_llm_for_analysis(prompt, system_prompt)

        # Parse response
        import re
        json_match = re.search(r'\[[\s\S]*\]', response)
        if json_match:
            prioritized = json.loads(json_match.group())
        else:
            prioritized = []

        # Sort by priority
        prioritized.sort(key=lambda x: x.get("priority", 5), reverse=True)

        if task_id and prioritized:
            target_list = "\n".join([
                f"  {i+1}. **{t['target']}** (Priority: {t['priority']}/10) - {t['reason'][:50]}..."
                for i, t in enumerate(prioritized[:5])
            ])

            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content=f"""### 🎯 Prioritized Scan Targets

{target_list}

Starting vulnerability assessment on high-priority targets...""",
                ),
                trace_id=trace_id,
            )

        return {
            "prioritized_targets": prioritized,
            "total_targets": len(prioritized),
            "high_priority_count": sum(1 for t in prioritized if t.get("priority", 0) >= 8),
        }

    except Exception as e:
        logger.error(f"Target prioritization failed: {e}")

        # Fallback: prioritize by change type
        fallback_targets = []
        for change in changes[:10]:
            fallback_targets.append({
                "target": change.get("asset_id", "unknown"),
                "priority": 8 if change["type"] == "new_asset" else 6,
                "reason": f"Detected change: {change['type']}",
                "recommended_tests": ["comprehensive"],
            })

        return {
            "prioritized_targets": fallback_targets,
            "total_targets": len(fallback_targets),
            "fallback": True,
        }


@activity.defn(name="schedule_continuous_scan_activity")
async def schedule_continuous_scan_activity(
    scope: Dict[str, Any],
    scan_interval_hours: int,
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Schedule and manage continuous scanning cycles.

    This activity:
    1. Determines when assets were last scanned
    2. Identifies assets due for re-scanning
    3. Schedules scans based on priority and interval
    4. Returns scan schedule
    """
    logger.info(f"Scheduling continuous scans with {scan_interval_hours}h interval")

    now = datetime.utcnow()
    scan_threshold = now - timedelta(hours=scan_interval_hours)

    # Find assets due for scanning
    due_for_scan = []
    for asset_id, last_scan in _attack_surface_state.last_scan_times.items():
        if last_scan < scan_threshold:
            asset = _attack_surface_state.known_assets.get(asset_id, {})
            due_for_scan.append({
                "asset_id": asset_id,
                "last_scan": last_scan.isoformat(),
                "hours_since_scan": (now - last_scan).total_seconds() / 3600,
                "asset_data": asset,
            })

    # Sort by time since last scan (oldest first)
    due_for_scan.sort(key=lambda x: x["hours_since_scan"], reverse=True)

    # Also include any new assets that haven't been scanned
    never_scanned = []
    for asset_id, asset in _attack_surface_state.known_assets.items():
        if asset_id not in _attack_surface_state.last_scan_times:
            never_scanned.append({
                "asset_id": asset_id,
                "last_scan": None,
                "hours_since_scan": float('inf'),
                "asset_data": asset,
            })

    # Combine and prioritize
    all_due = never_scanned + due_for_scan

    schedule = {
        "scan_interval_hours": scan_interval_hours,
        "assets_due_for_scan": len(all_due),
        "never_scanned": len(never_scanned),
        "overdue": len(due_for_scan),
        "scheduled_scans": all_due[:20],  # Limit batch size
        "next_check": (now + timedelta(hours=1)).isoformat(),
    }

    if task_id and all_due:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### ⏰ Continuous Scan Schedule

**Scan Interval:** Every {scan_interval_hours} hours
**Assets Due for Scan:** {len(all_due)}
  - Never scanned: {len(never_scanned)}
  - Overdue: {len(due_for_scan)}

Starting scheduled vulnerability scans...""",
            ),
            trace_id=trace_id,
        )

    return schedule