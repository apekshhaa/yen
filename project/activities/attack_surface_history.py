"""
Attack Surface History Persistence for Major-Project AI Pentester.

This module provides persistent storage for attack surface data:
- MongoDB-based storage for attack surface snapshots
- Change detection and diffing
- Historical trend analysis
- Alerting on new exposures
"""
import asyncio
import hashlib
import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from temporalio import activity

from agentex.lib.utils.logging import make_logger
from agentex.lib import adk
from agentex.types.text_content import TextContent

logger = make_logger(__name__)


# MongoDB connection settings
MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DATABASE = os.environ.get("MONGODB_DATABASE", "red_cell")


async def get_mongodb_client():
    """Get MongoDB client."""
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        client = AsyncIOMotorClient(MONGODB_URI)
        return client
    except ImportError:
        logger.warning("motor not installed, using in-memory storage")
        return None


class InMemoryStorage:
    """Fallback in-memory storage when MongoDB is not available."""

    _instance = None
    _data: Dict[str, List[Dict]] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._data = {}
        return cls._instance

    async def insert_one(self, collection: str, document: Dict) -> str:
        if collection not in self._data:
            self._data[collection] = []
        doc_id = hashlib.md5(json.dumps(document, default=str).encode()).hexdigest()
        document["_id"] = doc_id
        self._data[collection].append(document)
        return doc_id

    async def find(self, collection: str, query: Dict, sort: Optional[List] = None, limit: int = 100) -> List[Dict]:
        if collection not in self._data:
            return []

        results = []
        for doc in self._data[collection]:
            match = True
            for key, value in query.items():
                if key.startswith("$"):
                    continue
                if doc.get(key) != value:
                    match = False
                    break
            if match:
                results.append(doc)

        if sort:
            for field, direction in reversed(sort):
                results.sort(key=lambda x: x.get(field, ""), reverse=(direction == -1))

        return results[:limit]

    async def find_one(self, collection: str, query: Dict) -> Optional[Dict]:
        results = await self.find(collection, query, limit=1)
        return results[0] if results else None

    async def count_documents(self, collection: str, query: Dict) -> int:
        results = await self.find(collection, query, limit=10000)
        return len(results)


class AttackSurfaceStorage:
    """Storage interface for attack surface data."""

    def __init__(self):
        self._client = None
        self._db = None
        self._in_memory = None

    async def initialize(self):
        """Initialize storage connection."""
        self._client = await get_mongodb_client()
        if self._client:
            self._db = self._client[MONGODB_DATABASE]
        else:
            self._in_memory = InMemoryStorage()

    async def save_snapshot(self, organization_id: str, snapshot: Dict[str, Any]) -> str:
        """Save an attack surface snapshot."""
        document = {
            "organization_id": organization_id,
            "timestamp": datetime.utcnow(),
            "snapshot": snapshot,
            "hash": self._compute_hash(snapshot),
        }

        if self._db is not None:
            result = await self._db.attack_surface_snapshots.insert_one(document)
            return str(result.inserted_id)
        else:
            return await self._in_memory.insert_one("attack_surface_snapshots", document)

    async def get_latest_snapshot(self, organization_id: str) -> Optional[Dict[str, Any]]:
        """Get the most recent snapshot for an organization."""
        if self._db is not None:
            cursor = self._db.attack_surface_snapshots.find(
                {"organization_id": organization_id}
            ).sort("timestamp", -1).limit(1)
            async for doc in cursor:
                return doc
            return None
        else:
            results = await self._in_memory.find(
                "attack_surface_snapshots",
                {"organization_id": organization_id},
                sort=[("timestamp", -1)],
                limit=1
            )
            return results[0] if results else None

    async def get_snapshots(
        self,
        organization_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get snapshots within a date range."""
        query = {"organization_id": organization_id}

        if start_date or end_date:
            query["timestamp"] = {}
            if start_date:
                query["timestamp"]["$gte"] = start_date
            if end_date:
                query["timestamp"]["$lte"] = end_date

        if self._db is not None:
            cursor = self._db.attack_surface_snapshots.find(query).sort("timestamp", -1).limit(limit)
            return [doc async for doc in cursor]
        else:
            return await self._in_memory.find(
                "attack_surface_snapshots",
                query,
                sort=[("timestamp", -1)],
                limit=limit
            )

    async def save_change_event(self, organization_id: str, change: Dict[str, Any]) -> str:
        """Save a change event."""
        document = {
            "organization_id": organization_id,
            "timestamp": datetime.utcnow(),
            "change": change,
            "acknowledged": False,
        }

        if self._db is not None:
            result = await self._db.attack_surface_changes.insert_one(document)
            return str(result.inserted_id)
        else:
            return await self._in_memory.insert_one("attack_surface_changes", document)

    async def get_unacknowledged_changes(self, organization_id: str) -> List[Dict[str, Any]]:
        """Get unacknowledged changes for an organization."""
        query = {
            "organization_id": organization_id,
            "acknowledged": False,
        }

        if self._db is not None:
            cursor = self._db.attack_surface_changes.find(query).sort("timestamp", -1)
            return [doc async for doc in cursor]
        else:
            return await self._in_memory.find(
                "attack_surface_changes",
                query,
                sort=[("timestamp", -1)]
            )

    async def save_vulnerability(self, organization_id: str, vulnerability: Dict[str, Any]) -> str:
        """Save a discovered vulnerability."""
        document = {
            "organization_id": organization_id,
            "timestamp": datetime.utcnow(),
            "vulnerability": vulnerability,
            "status": "open",
            "hash": self._compute_hash(vulnerability),
        }

        if self._db is not None:
            result = await self._db.vulnerabilities.insert_one(document)
            return str(result.inserted_id)
        else:
            return await self._in_memory.insert_one("vulnerabilities", document)

    async def get_vulnerabilities(
        self,
        organization_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities for an organization."""
        query = {"organization_id": organization_id}

        if status:
            query["status"] = status
        if severity:
            query["vulnerability.severity"] = severity

        if self._db is not None:
            cursor = self._db.vulnerabilities.find(query).sort("timestamp", -1).limit(limit)
            return [doc async for doc in cursor]
        else:
            return await self._in_memory.find(
                "vulnerabilities",
                query,
                sort=[("timestamp", -1)],
                limit=limit
            )

    async def get_statistics(self, organization_id: str) -> Dict[str, Any]:
        """Get statistics for an organization."""
        if self._db is not None:
            snapshot_count = await self._db.attack_surface_snapshots.count_documents(
                {"organization_id": organization_id}
            )
            change_count = await self._db.attack_surface_changes.count_documents(
                {"organization_id": organization_id}
            )
            vuln_count = await self._db.vulnerabilities.count_documents(
                {"organization_id": organization_id, "status": "open"}
            )
        else:
            snapshot_count = await self._in_memory.count_documents(
                "attack_surface_snapshots",
                {"organization_id": organization_id}
            )
            change_count = await self._in_memory.count_documents(
                "attack_surface_changes",
                {"organization_id": organization_id}
            )
            vuln_count = await self._in_memory.count_documents(
                "vulnerabilities",
                {"organization_id": organization_id}
            )

        return {
            "total_snapshots": snapshot_count,
            "total_changes": change_count,
            "open_vulnerabilities": vuln_count,
        }

    def _compute_hash(self, data: Dict) -> str:
        """Compute a hash for deduplication."""
        return hashlib.sha256(
            json.dumps(data, sort_keys=True, default=str).encode()
        ).hexdigest()


# Global storage instance
_storage: Optional[AttackSurfaceStorage] = None


async def get_storage() -> AttackSurfaceStorage:
    """Get or create storage instance."""
    global _storage
    if _storage is None:
        _storage = AttackSurfaceStorage()
        await _storage.initialize()
    return _storage


@activity.defn(name="save_attack_surface_snapshot_activity")
async def save_attack_surface_snapshot_activity(
    organization_id: str,
    domains: List[str],
    subdomains: List[str],
    services: List[Dict[str, Any]],
    apis: List[Dict[str, Any]],
    technologies: List[str],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Save an attack surface snapshot to persistent storage.

    This activity:
    1. Creates a snapshot of the current attack surface
    2. Compares with previous snapshot to detect changes
    3. Saves the snapshot and any changes
    4. Returns change summary
    """
    logger.info(f"Saving attack surface snapshot for {organization_id}")

    activity.heartbeat("Saving attack surface snapshot")

    storage = await get_storage()

    # Create snapshot
    snapshot = {
        "domains": sorted(domains),
        "subdomains": sorted(subdomains),
        "services": services,
        "apis": apis,
        "technologies": sorted(technologies),
        "asset_count": len(domains) + len(subdomains) + len(services) + len(apis),
    }

    # Get previous snapshot for comparison
    previous = await storage.get_latest_snapshot(organization_id)

    changes = {
        "new_domains": [],
        "removed_domains": [],
        "new_subdomains": [],
        "removed_subdomains": [],
        "new_services": [],
        "removed_services": [],
        "new_apis": [],
        "removed_apis": [],
        "new_technologies": [],
        "removed_technologies": [],
    }

    if previous:
        prev_snapshot = previous.get("snapshot", {})

        # Compare domains
        prev_domains = set(prev_snapshot.get("domains", []))
        curr_domains = set(domains)
        changes["new_domains"] = list(curr_domains - prev_domains)
        changes["removed_domains"] = list(prev_domains - curr_domains)

        # Compare subdomains
        prev_subdomains = set(prev_snapshot.get("subdomains", []))
        curr_subdomains = set(subdomains)
        changes["new_subdomains"] = list(curr_subdomains - prev_subdomains)
        changes["removed_subdomains"] = list(prev_subdomains - curr_subdomains)

        # Compare technologies
        prev_tech = set(prev_snapshot.get("technologies", []))
        curr_tech = set(technologies)
        changes["new_technologies"] = list(curr_tech - prev_tech)
        changes["removed_technologies"] = list(prev_tech - curr_tech)

        # Compare services (by host:port)
        prev_services = {f"{s.get('host')}:{s.get('port')}" for s in prev_snapshot.get("services", [])}
        curr_services = {f"{s.get('host')}:{s.get('port')}" for s in services}
        changes["new_services"] = list(curr_services - prev_services)
        changes["removed_services"] = list(prev_services - curr_services)

        # Compare APIs (by endpoint)
        prev_apis = {a.get("endpoint", a.get("url", "")) for a in prev_snapshot.get("apis", [])}
        curr_apis = {a.get("endpoint", a.get("url", "")) for a in apis}
        changes["new_apis"] = list(curr_apis - prev_apis)
        changes["removed_apis"] = list(prev_apis - curr_apis)

    # Save snapshot
    snapshot_id = await storage.save_snapshot(organization_id, snapshot)

    # Save change events if there are changes
    has_changes = any(
        changes[key] for key in changes
    )

    if has_changes:
        await storage.save_change_event(organization_id, changes)

    # Calculate change summary
    total_new = (
        len(changes["new_domains"]) +
        len(changes["new_subdomains"]) +
        len(changes["new_services"]) +
        len(changes["new_apis"])
    )
    total_removed = (
        len(changes["removed_domains"]) +
        len(changes["removed_subdomains"]) +
        len(changes["removed_services"]) +
        len(changes["removed_apis"])
    )

    # Notify about snapshot
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 💾 Attack Surface Snapshot Saved

**Organization:** {organization_id}
**Snapshot ID:** {snapshot_id}
**Total Assets:** {snapshot['asset_count']}

**Changes Detected:**
- New Domains: {len(changes['new_domains'])}
- Removed Domains: {len(changes['removed_domains'])}
- New Subdomains: {len(changes['new_subdomains'])}
- Removed Subdomains: {len(changes['removed_subdomains'])}
- New Services: {len(changes['new_services'])}
- New APIs: {len(changes['new_apis'])}

**Summary:** {total_new} new assets, {total_removed} removed assets
""",
            ),
            trace_id=trace_id,
        )

    return {
        "snapshot_id": snapshot_id,
        "organization_id": organization_id,
        "asset_count": snapshot["asset_count"],
        "changes": changes,
        "has_changes": has_changes,
        "total_new": total_new,
        "total_removed": total_removed,
    }


@activity.defn(name="get_attack_surface_history_activity")
async def get_attack_surface_history_activity(
    organization_id: str,
    days: int,
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Get attack surface history for trend analysis.

    This activity:
    1. Retrieves historical snapshots
    2. Calculates trends over time
    3. Identifies growth patterns
    4. Returns historical data
    """
    logger.info(f"Getting attack surface history for {organization_id}")

    activity.heartbeat("Getting attack surface history")

    storage = await get_storage()

    # Calculate date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)

    # Get snapshots
    snapshots = await storage.get_snapshots(
        organization_id,
        start_date=start_date,
        end_date=end_date,
        limit=100
    )

    # Calculate trends
    history = []
    for snapshot in snapshots:
        snap_data = snapshot.get("snapshot", {})
        history.append({
            "timestamp": snapshot.get("timestamp"),
            "domains": len(snap_data.get("domains", [])),
            "subdomains": len(snap_data.get("subdomains", [])),
            "services": len(snap_data.get("services", [])),
            "apis": len(snap_data.get("apis", [])),
            "total_assets": snap_data.get("asset_count", 0),
        })

    # Calculate growth
    if len(history) >= 2:
        oldest = history[-1]
        newest = history[0]

        growth = {
            "domains": newest["domains"] - oldest["domains"],
            "subdomains": newest["subdomains"] - oldest["subdomains"],
            "services": newest["services"] - oldest["services"],
            "apis": newest["apis"] - oldest["apis"],
            "total_assets": newest["total_assets"] - oldest["total_assets"],
        }

        growth_rate = {
            "domains": (growth["domains"] / max(oldest["domains"], 1)) * 100,
            "subdomains": (growth["subdomains"] / max(oldest["subdomains"], 1)) * 100,
            "total_assets": (growth["total_assets"] / max(oldest["total_assets"], 1)) * 100,
        }
    else:
        growth = {"domains": 0, "subdomains": 0, "services": 0, "apis": 0, "total_assets": 0}
        growth_rate = {"domains": 0, "subdomains": 0, "total_assets": 0}

    # Get statistics
    stats = await storage.get_statistics(organization_id)

    # Notify about history
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 📊 Attack Surface History

**Organization:** {organization_id}
**Period:** Last {days} days
**Snapshots:** {len(history)}

**Current State:**
- Domains: {history[0]['domains'] if history else 0}
- Subdomains: {history[0]['subdomains'] if history else 0}
- Services: {history[0]['services'] if history else 0}
- APIs: {history[0]['apis'] if history else 0}

**Growth (Period):**
- Domains: {growth['domains']:+d} ({growth_rate['domains']:.1f}%)
- Subdomains: {growth['subdomains']:+d} ({growth_rate['subdomains']:.1f}%)
- Total Assets: {growth['total_assets']:+d} ({growth_rate['total_assets']:.1f}%)

**Statistics:**
- Total Snapshots: {stats['total_snapshots']}
- Total Changes: {stats['total_changes']}
- Open Vulnerabilities: {stats['open_vulnerabilities']}
""",
            ),
            trace_id=trace_id,
        )

    return {
        "organization_id": organization_id,
        "period_days": days,
        "snapshots_count": len(history),
        "history": history,
        "growth": growth,
        "growth_rate": growth_rate,
        "statistics": stats,
    }


@activity.defn(name="detect_attack_surface_changes_activity")
async def detect_attack_surface_changes_activity(
    organization_id: str,
    current_snapshot: Dict[str, Any],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Detect changes in attack surface compared to previous state.

    This activity:
    1. Compares current state with previous snapshot
    2. Identifies new and removed assets
    3. Categorizes changes by risk level
    4. Returns detailed change report
    """
    logger.info(f"Detecting attack surface changes for {organization_id}")

    activity.heartbeat("Detecting attack surface changes")

    storage = await get_storage()

    # Get previous snapshot
    previous = await storage.get_latest_snapshot(organization_id)

    if not previous:
        # First snapshot, everything is new
        return {
            "organization_id": organization_id,
            "is_first_snapshot": True,
            "changes": {
                "new_assets": current_snapshot.get("asset_count", 0),
                "removed_assets": 0,
            },
            "risk_level": "info",
        }

    prev_snapshot = previous.get("snapshot", {})

    # Detailed comparison
    changes = {
        "new_domains": [],
        "removed_domains": [],
        "new_subdomains": [],
        "removed_subdomains": [],
        "new_services": [],
        "removed_services": [],
        "new_apis": [],
        "removed_apis": [],
        "new_technologies": [],
        "removed_technologies": [],
    }

    # Compare each category
    prev_domains = set(prev_snapshot.get("domains", []))
    curr_domains = set(current_snapshot.get("domains", []))
    changes["new_domains"] = list(curr_domains - prev_domains)
    changes["removed_domains"] = list(prev_domains - curr_domains)

    prev_subdomains = set(prev_snapshot.get("subdomains", []))
    curr_subdomains = set(current_snapshot.get("subdomains", []))
    changes["new_subdomains"] = list(curr_subdomains - prev_subdomains)
    changes["removed_subdomains"] = list(prev_subdomains - curr_subdomains)

    prev_tech = set(prev_snapshot.get("technologies", []))
    curr_tech = set(current_snapshot.get("technologies", []))
    changes["new_technologies"] = list(curr_tech - prev_tech)
    changes["removed_technologies"] = list(prev_tech - curr_tech)

    # Services comparison
    prev_services = {f"{s.get('host')}:{s.get('port')}" for s in prev_snapshot.get("services", [])}
    curr_services = {f"{s.get('host')}:{s.get('port')}" for s in current_snapshot.get("services", [])}
    changes["new_services"] = list(curr_services - prev_services)
    changes["removed_services"] = list(prev_services - curr_services)

    # APIs comparison
    prev_apis = {a.get("endpoint", a.get("url", "")) for a in prev_snapshot.get("apis", [])}
    curr_apis = {a.get("endpoint", a.get("url", "")) for a in current_snapshot.get("apis", [])}
    changes["new_apis"] = list(curr_apis - prev_apis)
    changes["removed_apis"] = list(prev_apis - curr_apis)

    # Calculate risk level based on changes
    high_risk_indicators = [
        len(changes["new_services"]) > 5,
        len(changes["new_apis"]) > 10,
        any("admin" in s.lower() for s in changes["new_subdomains"]),
        any("internal" in s.lower() for s in changes["new_subdomains"]),
        any("dev" in s.lower() for s in changes["new_subdomains"]),
        any("staging" in s.lower() for s in changes["new_subdomains"]),
    ]

    medium_risk_indicators = [
        len(changes["new_domains"]) > 0,
        len(changes["new_subdomains"]) > 10,
        len(changes["new_services"]) > 0,
    ]

    if any(high_risk_indicators):
        risk_level = "high"
    elif any(medium_risk_indicators):
        risk_level = "medium"
    elif any(changes[key] for key in changes):
        risk_level = "low"
    else:
        risk_level = "none"

    # Calculate totals
    total_new = sum(len(changes[key]) for key in changes if key.startswith("new_"))
    total_removed = sum(len(changes[key]) for key in changes if key.startswith("removed_"))

    # Notify about changes
    if task_id and (total_new > 0 or total_removed > 0):
        risk_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢", "none": "⚪"}.get(risk_level, "⚪")

        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🔄 Attack Surface Changes Detected

**Organization:** {organization_id}
**Risk Level:** {risk_emoji} {risk_level.upper()}

**New Assets ({total_new}):**
- Domains: {len(changes['new_domains'])}
- Subdomains: {len(changes['new_subdomains'])}
- Services: {len(changes['new_services'])}
- APIs: {len(changes['new_apis'])}

**Removed Assets ({total_removed}):**
- Domains: {len(changes['removed_domains'])}
- Subdomains: {len(changes['removed_subdomains'])}
- Services: {len(changes['removed_services'])}
- APIs: {len(changes['removed_apis'])}

**Notable New Subdomains:**
{chr(10).join([f"- `{s}`" for s in changes['new_subdomains'][:10]])}
""",
            ),
            trace_id=trace_id,
        )

    return {
        "organization_id": organization_id,
        "is_first_snapshot": False,
        "changes": changes,
        "risk_level": risk_level,
        "total_new": total_new,
        "total_removed": total_removed,
        "previous_timestamp": previous.get("timestamp"),
    }


@activity.defn(name="save_vulnerability_finding_activity")
async def save_vulnerability_finding_activity(
    organization_id: str,
    vulnerability: Dict[str, Any],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Save a vulnerability finding to persistent storage.

    This activity:
    1. Saves the vulnerability with metadata
    2. Checks for duplicates
    3. Updates statistics
    4. Returns save confirmation
    """
    logger.info(f"Saving vulnerability for {organization_id}")

    activity.heartbeat("Saving vulnerability")

    storage = await get_storage()

    # Save vulnerability
    vuln_id = await storage.save_vulnerability(organization_id, vulnerability)

    # Get updated statistics
    stats = await storage.get_statistics(organization_id)

    # Notify about save
    if task_id:
        severity = vulnerability.get("severity", "unknown").upper()
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }.get(severity, "⚪")

        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 💾 Vulnerability Saved

**ID:** {vuln_id}
**Severity:** {severity_emoji} {severity}
**Type:** {vulnerability.get('type', 'Unknown')}
**Target:** {vulnerability.get('target', 'Unknown')}

**Open Vulnerabilities:** {stats['open_vulnerabilities']}
""",
            ),
            trace_id=trace_id,
        )

    return {
        "vulnerability_id": vuln_id,
        "organization_id": organization_id,
        "severity": vulnerability.get("severity"),
        "statistics": stats,
    }


@activity.defn(name="get_vulnerability_trends_activity")
async def get_vulnerability_trends_activity(
    organization_id: str,
    days: int,
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Get vulnerability trends over time.

    This activity:
    1. Retrieves historical vulnerability data
    2. Calculates trends by severity
    3. Identifies patterns
    4. Returns trend analysis
    """
    logger.info(f"Getting vulnerability trends for {organization_id}")

    activity.heartbeat("Getting vulnerability trends")

    storage = await get_storage()

    # Get all vulnerabilities
    vulnerabilities = await storage.get_vulnerabilities(organization_id, limit=1000)

    # Calculate date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)

    # Filter by date and categorize
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_status = {"open": 0, "closed": 0, "in_progress": 0}
    by_type = {}

    for vuln in vulnerabilities:
        timestamp = vuln.get("timestamp")
        if timestamp and start_date <= timestamp <= end_date:
            severity = vuln.get("vulnerability", {}).get("severity", "unknown").lower()
            if severity in by_severity:
                by_severity[severity] += 1

            status = vuln.get("status", "open")
            if status in by_status:
                by_status[status] += 1

            vuln_type = vuln.get("vulnerability", {}).get("type", "unknown")
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1

    total = sum(by_severity.values())

    # Notify about trends
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 📈 Vulnerability Trends

**Organization:** {organization_id}
**Period:** Last {days} days
**Total Vulnerabilities:** {total}

**By Severity:**
- 🔴 Critical: {by_severity['critical']}
- 🟠 High: {by_severity['high']}
- 🟡 Medium: {by_severity['medium']}
- 🟢 Low: {by_severity['low']}

**By Status:**
- Open: {by_status['open']}
- In Progress: {by_status['in_progress']}
- Closed: {by_status['closed']}

**Top Vulnerability Types:**
{chr(10).join([f"- {t}: {c}" for t, c in sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:5]])}
""",
            ),
            trace_id=trace_id,
        )

    return {
        "organization_id": organization_id,
        "period_days": days,
        "total_vulnerabilities": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_type": by_type,
    }