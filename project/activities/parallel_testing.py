"""
Parallel Testing Engine for High-Speed Vulnerability Assessment.

This module implements parallel testing capabilities that enable:

1. Concurrent Endpoint Testing - Test multiple endpoints simultaneously
2. Distributed Scanning - Spread load across multiple workers
3. Rate-Limited Parallelism - Respect target rate limits while maximizing speed
4. Result Aggregation - Combine findings from parallel tests
5. Smart Scheduling - Prioritize high-value targets

This enables "testing endpoints faster and more thoroughly than human pentesters"
by leveraging parallelism and intelligent scheduling.
"""
import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from enum import Enum

from temporalio import activity

from agentex.lib.utils.logging import make_logger
from agentex.lib import adk
from agentex.types.text_content import TextContent

logger = make_logger(__name__)


class TestPriority(Enum):
    """Priority levels for test scheduling."""
    CRITICAL = 1  # Known vulnerable patterns
    HIGH = 2      # High-value endpoints (auth, admin)
    MEDIUM = 3    # Standard endpoints
    LOW = 4       # Static resources, low-risk


@dataclass
class TestTask:
    """Represents a single test task."""
    id: str
    endpoint: str
    test_type: str
    payload: str
    priority: TestPriority = TestPriority.MEDIUM
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    retries: int = 0
    max_retries: int = 2


@dataclass
class RateLimiter:
    """Token bucket rate limiter for respecting target limits."""
    requests_per_second: float
    burst_size: int
    tokens: float = field(default=0.0)
    last_update: float = field(default_factory=time.time)

    def acquire(self) -> bool:
        """Try to acquire a token. Returns True if successful."""
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.burst_size, self.tokens + elapsed * self.requests_per_second)
        self.last_update = now

        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

    async def wait_for_token(self):
        """Wait until a token is available."""
        while not self.acquire():
            await asyncio.sleep(0.1)


class ParallelTestEngine:
    """Engine for running tests in parallel with intelligent scheduling."""

    def __init__(
        self,
        max_concurrent: int = 20,
        requests_per_second: float = 50.0,
        burst_size: int = 100,
    ):
        self.max_concurrent = max_concurrent
        self.rate_limiter = RateLimiter(requests_per_second, burst_size, burst_size)
        self.pending_tasks: List[TestTask] = []
        self.running_tasks: Set[str] = set()
        self.completed_tasks: List[TestTask] = []
        self.failed_tasks: List[TestTask] = []
        self.results: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max_concurrent)

    def add_task(self, task: TestTask):
        """Add a task to the pending queue."""
        self.pending_tasks.append(task)

    def add_tasks(self, tasks: List[TestTask]):
        """Add multiple tasks to the pending queue."""
        self.pending_tasks.extend(tasks)

    def _sort_by_priority(self):
        """Sort pending tasks by priority."""
        self.pending_tasks.sort(key=lambda t: (t.priority.value, t.created_at))

    async def execute_task(
        self,
        task: TestTask,
        executor: Callable[[TestTask], Any],
    ) -> TestTask:
        """Execute a single task with rate limiting and error handling."""
        async with self._semaphore:
            await self.rate_limiter.wait_for_token()

            async with self._lock:
                self.running_tasks.add(task.id)

            task.started_at = datetime.utcnow()

            try:
                result = await executor(task)
                task.result = result
                task.completed_at = datetime.utcnow()

                async with self._lock:
                    self.running_tasks.discard(task.id)
                    self.completed_tasks.append(task)
                    self.results[task.id] = result

            except Exception as e:
                task.error = str(e)
                task.retries += 1

                async with self._lock:
                    self.running_tasks.discard(task.id)

                    if task.retries < task.max_retries:
                        # Re-queue for retry
                        self.pending_tasks.append(task)
                    else:
                        self.failed_tasks.append(task)

            return task

    async def run_all(
        self,
        executor: Callable[[TestTask], Any],
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
    ) -> Dict[str, Any]:
        """Run all pending tasks in parallel."""
        self._sort_by_priority()

        total_tasks = len(self.pending_tasks)
        tasks_to_run = self.pending_tasks.copy()
        self.pending_tasks.clear()

        # Create coroutines for all tasks
        async def run_with_progress(task: TestTask):
            result = await self.execute_task(task, executor)
            if progress_callback:
                progress_callback(
                    len(self.completed_tasks),
                    len(self.failed_tasks),
                    total_tasks,
                )
            return result

        # Run all tasks concurrently
        await asyncio.gather(
            *[run_with_progress(task) for task in tasks_to_run],
            return_exceptions=True,
        )

        return {
            "total": total_tasks,
            "completed": len(self.completed_tasks),
            "failed": len(self.failed_tasks),
            "results": self.results,
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get execution statistics."""
        completed_times = [
            (t.completed_at - t.started_at).total_seconds()
            for t in self.completed_tasks
            if t.completed_at and t.started_at
        ]

        return {
            "total_completed": len(self.completed_tasks),
            "total_failed": len(self.failed_tasks),
            "total_pending": len(self.pending_tasks),
            "currently_running": len(self.running_tasks),
            "avg_execution_time": sum(completed_times) / len(completed_times) if completed_times else 0,
            "min_execution_time": min(completed_times) if completed_times else 0,
            "max_execution_time": max(completed_times) if completed_times else 0,
        }


# =============================================================================
# PARALLEL VULNERABILITY SCANNING
# =============================================================================

async def _execute_vuln_test(task: TestTask) -> Dict[str, Any]:
    """Execute a single vulnerability test."""
    from urllib.parse import quote, urlparse, parse_qs, urlencode, urlunparse

    try:
        endpoint = task.endpoint
        payload = task.payload
        test_type = task.test_type

        # Build test URL
        parsed = urlparse(endpoint)
        params = parse_qs(parsed.query)

        # Find first parameter to inject
        if params:
            param_name = list(params.keys())[0]
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        else:
            test_url = f"{endpoint}?test={quote(payload, safe='')}"

        # Execute request
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "-w", "\n%{http_code}\n%{size_download}\n%{time_total}",
            "-m", "10", test_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode(errors='ignore')
        lines = output.strip().split('\n')

        if len(lines) >= 3:
            status = int(lines[-3]) if lines[-3].isdigit() else 0
            length = int(lines[-2]) if lines[-2].isdigit() else 0
            time_taken = float(lines[-1]) if lines[-1].replace('.', '').isdigit() else 0
            body = '\n'.join(lines[:-3])
        else:
            status = 0
            length = 0
            time_taken = 0
            body = output

        # Analyze for vulnerabilities
        vulnerable = False
        indicators = []

        # Check for reflection (XSS indicator)
        if payload in body:
            indicators.append("payload_reflected")
            if test_type == "xss":
                vulnerable = True

        # Check for error messages (SQLi indicator)
        sql_errors = ["sql", "syntax", "mysql", "postgresql", "oracle", "sqlite"]
        for err in sql_errors:
            if err in body.lower():
                indicators.append(f"sql_error_{err}")
                if test_type == "sqli":
                    vulnerable = True

        # Check for server errors
        if status >= 500:
            indicators.append("server_error")
            vulnerable = True

        # Check for path traversal indicators
        if test_type == "path_traversal":
            path_indicators = ["root:", "/etc/", "boot.ini", "[extensions]"]
            for ind in path_indicators:
                if ind in body:
                    indicators.append(f"path_traversal_{ind}")
                    vulnerable = True

        # Check for SSRF indicators
        if test_type == "ssrf":
            ssrf_indicators = ["connection refused", "timeout", "could not resolve"]
            for ind in ssrf_indicators:
                if ind in body.lower():
                    indicators.append(f"ssrf_{ind}")

        return {
            "endpoint": endpoint,
            "test_type": test_type,
            "payload": payload[:100],
            "status_code": status,
            "response_length": length,
            "time_taken": time_taken,
            "vulnerable": vulnerable,
            "indicators": indicators,
            "response_sample": body[:300] if vulnerable else "",
        }

    except Exception as e:
        return {
            "endpoint": task.endpoint,
            "test_type": task.test_type,
            "error": str(e),
            "vulnerable": False,
        }


@activity.defn(name="parallel_vulnerability_scan_activity")
async def parallel_vulnerability_scan_activity(
    endpoints: List[str],
    test_types: List[str],
    payloads_per_type: Dict[str, List[str]],
    max_concurrent: int,
    requests_per_second: float,
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Perform parallel vulnerability scanning across multiple endpoints.

    This activity:
    1. Creates test tasks for all endpoint/payload combinations
    2. Prioritizes tests based on endpoint characteristics
    3. Executes tests in parallel with rate limiting
    4. Aggregates and reports findings
    """
    logger.info(f"Starting parallel scan of {len(endpoints)} endpoints with {len(test_types)} test types")

    activity.heartbeat("Initializing parallel scan engine")

    engine = ParallelTestEngine(
        max_concurrent=max_concurrent,
        requests_per_second=requests_per_second,
    )

    # Create test tasks
    task_count = 0
    for endpoint in endpoints:
        # Determine priority based on endpoint
        priority = TestPriority.MEDIUM
        endpoint_lower = endpoint.lower()

        if any(p in endpoint_lower for p in ["admin", "login", "auth", "api/v"]):
            priority = TestPriority.HIGH
        elif any(p in endpoint_lower for p in ["upload", "exec", "eval", "system"]):
            priority = TestPriority.CRITICAL
        elif any(p in endpoint_lower for p in ["static", "assets", "images", "css", "js"]):
            priority = TestPriority.LOW

        for test_type in test_types:
            payloads = payloads_per_type.get(test_type, [])[:10]  # Limit payloads per type

            for payload in payloads:
                task = TestTask(
                    id=f"task_{task_count}",
                    endpoint=endpoint,
                    test_type=test_type,
                    payload=payload,
                    priority=priority,
                )
                engine.add_task(task)
                task_count += 1

    logger.info(f"Created {task_count} test tasks")

    # Progress tracking
    last_heartbeat = [0]

    def progress_callback(completed: int, failed: int, total: int):
        if completed - last_heartbeat[0] >= 50:  # Heartbeat every 50 tasks
            activity.heartbeat(f"Progress: {completed}/{total} ({failed} failed)")
            last_heartbeat[0] = completed

    # Run all tests
    activity.heartbeat("Running parallel tests")
    results = await engine.run_all(_execute_vuln_test, progress_callback)

    # Aggregate findings
    vulnerabilities = []
    by_type = defaultdict(list)
    by_endpoint = defaultdict(list)

    for task_id_key, result in results.get("results", {}).items():
        if result.get("vulnerable"):
            vulnerabilities.append(result)
            by_type[result.get("test_type", "unknown")].append(result)
            by_endpoint[result.get("endpoint", "unknown")].append(result)

    stats = engine.get_statistics()

    # Notify about findings
    if task_id:
        vuln_summary = "\n".join([
            f"- **{vtype}**: {len(vulns)} findings"
            for vtype, vulns in by_type.items()
        ])

        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### ⚡ Parallel Vulnerability Scan Complete

**Endpoints Tested:** {len(endpoints)}
**Total Tests:** {task_count}
**Completed:** {stats['total_completed']}
**Failed:** {stats['total_failed']}
**Avg Time/Test:** {stats['avg_execution_time']:.2f}s

**Vulnerabilities Found:** {len(vulnerabilities)}

**By Type:**
{vuln_summary if vuln_summary else "No vulnerabilities found"}

**Most Vulnerable Endpoints:**
{chr(10).join([f"- `{ep[:50]}...` ({len(vulns)} vulns)" for ep, vulns in sorted(by_endpoint.items(), key=lambda x: len(x[1]), reverse=True)[:5]])}

Parallel testing completed {task_count} tests in record time!""",
            ),
            trace_id=trace_id,
        )

    return {
        "endpoints_tested": len(endpoints),
        "total_tests": task_count,
        "statistics": stats,
        "vulnerabilities": vulnerabilities,
        "by_type": {k: len(v) for k, v in by_type.items()},
        "by_endpoint": {k: len(v) for k, v in by_endpoint.items()},
    }


# =============================================================================
# SMART ENDPOINT PRIORITIZATION
# =============================================================================

@activity.defn(name="prioritize_endpoints_activity")
async def prioritize_endpoints_activity(
    endpoints: List[str],
    technologies: List[str],
    previous_findings: List[Dict[str, Any]],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Intelligently prioritize endpoints for testing.

    This activity:
    1. Analyzes endpoint patterns
    2. Considers technology stack
    3. Learns from previous findings
    4. Returns prioritized endpoint list
    """
    logger.info(f"Prioritizing {len(endpoints)} endpoints")

    activity.heartbeat("Analyzing endpoints for prioritization")

    # Scoring criteria
    priority_patterns = {
        TestPriority.CRITICAL: [
            r"admin", r"root", r"superuser", r"exec", r"eval", r"system",
            r"upload", r"import", r"backup", r"restore", r"config",
        ],
        TestPriority.HIGH: [
            r"login", r"auth", r"signin", r"signup", r"register",
            r"password", r"reset", r"token", r"session", r"api/v\d",
            r"user", r"account", r"profile", r"settings",
        ],
        TestPriority.MEDIUM: [
            r"search", r"query", r"filter", r"sort", r"page",
            r"id=", r"file=", r"path=", r"url=", r"redirect",
        ],
        TestPriority.LOW: [
            r"static", r"assets", r"images", r"css", r"js",
            r"fonts", r"icons", r"favicon", r"robots\.txt",
        ],
    }

    # Score each endpoint
    scored_endpoints = []

    for endpoint in endpoints:
        endpoint_lower = endpoint.lower()
        score = 50  # Base score
        priority = TestPriority.MEDIUM
        reasons = []

        # Check patterns
        for prio, patterns in priority_patterns.items():
            for pattern in patterns:
                if re.search(pattern, endpoint_lower):
                    if prio.value < priority.value:
                        priority = prio
                    if prio == TestPriority.CRITICAL:
                        score += 30
                        reasons.append(f"critical_pattern:{pattern}")
                    elif prio == TestPriority.HIGH:
                        score += 20
                        reasons.append(f"high_pattern:{pattern}")
                    elif prio == TestPriority.LOW:
                        score -= 20
                        reasons.append(f"low_pattern:{pattern}")

        # Check for parameters (more interesting)
        if "?" in endpoint:
            param_count = endpoint.count("&") + 1
            score += min(param_count * 5, 25)
            reasons.append(f"has_params:{param_count}")

        # Check for dynamic segments
        if re.search(r'/\d+/', endpoint) or re.search(r'/[a-f0-9-]{36}/', endpoint):
            score += 10
            reasons.append("dynamic_segment")

        # Boost based on previous findings
        for finding in previous_findings:
            if finding.get("endpoint", "").split("?")[0] == endpoint.split("?")[0]:
                score += 15
                reasons.append("previous_finding")
                break

        scored_endpoints.append({
            "endpoint": endpoint,
            "score": score,
            "priority": priority.name,
            "reasons": reasons,
        })

    # Sort by score (descending)
    scored_endpoints.sort(key=lambda x: x["score"], reverse=True)

    # Group by priority
    by_priority = defaultdict(list)
    for ep in scored_endpoints:
        by_priority[ep["priority"]].append(ep)

    # Notify about prioritization
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🎯 Endpoint Prioritization Complete

**Total Endpoints:** {len(endpoints)}

**By Priority:**
- 🔴 Critical: {len(by_priority.get('CRITICAL', []))}
- 🟠 High: {len(by_priority.get('HIGH', []))}
- 🟡 Medium: {len(by_priority.get('MEDIUM', []))}
- 🟢 Low: {len(by_priority.get('LOW', []))}

**Top Priority Endpoints:**
{chr(10).join([f"- `{ep['endpoint'][:60]}...` (Score: {ep['score']})" for ep in scored_endpoints[:5]])}

Endpoints have been prioritized for maximum vulnerability discovery efficiency.""",
            ),
            trace_id=trace_id,
        )

    return {
        "total_endpoints": len(endpoints),
        "prioritized_endpoints": [ep["endpoint"] for ep in scored_endpoints],
        "scored_endpoints": scored_endpoints,
        "by_priority": {k: len(v) for k, v in by_priority.items()},
    }


# =============================================================================
# DISTRIBUTED SCANNING COORDINATION
# =============================================================================

@dataclass
class ScanChunk:
    """A chunk of endpoints to be scanned by a worker."""
    chunk_id: str
    endpoints: List[str]
    test_types: List[str]
    priority: TestPriority
    assigned_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results: Optional[Dict[str, Any]] = None


class DistributedScanCoordinator:
    """Coordinates distributed scanning across multiple workers."""

    def __init__(self, chunk_size: int = 50):
        self.chunk_size = chunk_size
        self.chunks: List[ScanChunk] = []
        self.completed_chunks: List[ScanChunk] = []
        self.aggregated_results: Dict[str, Any] = {
            "vulnerabilities": [],
            "by_type": defaultdict(list),
            "by_endpoint": defaultdict(list),
        }

    def create_chunks(
        self,
        endpoints: List[str],
        test_types: List[str],
        priorities: Dict[str, TestPriority],
    ) -> List[ScanChunk]:
        """Create scan chunks from endpoints."""
        # Group endpoints by priority
        by_priority = defaultdict(list)
        for endpoint in endpoints:
            priority = priorities.get(endpoint, TestPriority.MEDIUM)
            by_priority[priority].append(endpoint)

        # Create chunks, prioritizing critical/high first
        chunk_id = 0
        for priority in [TestPriority.CRITICAL, TestPriority.HIGH, TestPriority.MEDIUM, TestPriority.LOW]:
            priority_endpoints = by_priority[priority]

            for i in range(0, len(priority_endpoints), self.chunk_size):
                chunk_endpoints = priority_endpoints[i:i + self.chunk_size]
                chunk = ScanChunk(
                    chunk_id=f"chunk_{chunk_id}",
                    endpoints=chunk_endpoints,
                    test_types=test_types,
                    priority=priority,
                )
                self.chunks.append(chunk)
                chunk_id += 1

        return self.chunks

    def get_next_chunk(self) -> Optional[ScanChunk]:
        """Get the next unassigned chunk."""
        for chunk in self.chunks:
            if chunk.assigned_at is None:
                chunk.assigned_at = datetime.utcnow()
                return chunk
        return None

    def complete_chunk(self, chunk_id: str, results: Dict[str, Any]):
        """Mark a chunk as completed and aggregate results."""
        for chunk in self.chunks:
            if chunk.chunk_id == chunk_id:
                chunk.completed_at = datetime.utcnow()
                chunk.results = results
                self.completed_chunks.append(chunk)

                # Aggregate results
                for vuln in results.get("vulnerabilities", []):
                    self.aggregated_results["vulnerabilities"].append(vuln)
                    self.aggregated_results["by_type"][vuln.get("test_type", "unknown")].append(vuln)
                    self.aggregated_results["by_endpoint"][vuln.get("endpoint", "unknown")].append(vuln)

                break

    def get_progress(self) -> Dict[str, Any]:
        """Get current progress."""
        total = len(self.chunks)
        completed = len(self.completed_chunks)
        assigned = len([c for c in self.chunks if c.assigned_at is not None])

        return {
            "total_chunks": total,
            "completed_chunks": completed,
            "assigned_chunks": assigned,
            "pending_chunks": total - assigned,
            "progress_percent": (completed / total * 100) if total > 0 else 0,
        }


@activity.defn(name="coordinate_distributed_scan_activity")
async def coordinate_distributed_scan_activity(
    endpoints: List[str],
    test_types: List[str],
    chunk_size: int,
    max_concurrent_chunks: int,
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Coordinate a distributed scan across multiple parallel workers.

    This activity:
    1. Divides endpoints into chunks
    2. Assigns chunks to parallel workers
    3. Aggregates results from all workers
    4. Reports comprehensive findings
    """
    logger.info(f"Coordinating distributed scan of {len(endpoints)} endpoints")

    activity.heartbeat("Creating scan chunks")

    coordinator = DistributedScanCoordinator(chunk_size=chunk_size)

    # Create priority map
    priorities = {}
    for endpoint in endpoints:
        endpoint_lower = endpoint.lower()
        if any(p in endpoint_lower for p in ["admin", "exec", "upload"]):
            priorities[endpoint] = TestPriority.CRITICAL
        elif any(p in endpoint_lower for p in ["login", "auth", "api"]):
            priorities[endpoint] = TestPriority.HIGH
        elif any(p in endpoint_lower for p in ["static", "assets"]):
            priorities[endpoint] = TestPriority.LOW
        else:
            priorities[endpoint] = TestPriority.MEDIUM

    chunks = coordinator.create_chunks(endpoints, test_types, priorities)

    logger.info(f"Created {len(chunks)} scan chunks")

    # Default payloads for testing
    default_payloads = {
        "sqli": ["'", "\"", "1' OR '1'='1", "1; DROP TABLE users--"],
        "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        "path_traversal": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"],
        "ssrf": ["http://127.0.0.1", "http://localhost:22"],
        "cmd_injection": ["; ls", "| cat /etc/passwd", "`id`"],
    }

    # Process chunks in parallel
    async def process_chunk(chunk: ScanChunk) -> Dict[str, Any]:
        activity.heartbeat(f"Processing {chunk.chunk_id}")

        engine = ParallelTestEngine(max_concurrent=10, requests_per_second=20.0)

        task_count = 0
        for endpoint in chunk.endpoints:
            for test_type in chunk.test_types:
                payloads = default_payloads.get(test_type, [])[:5]
                for payload in payloads:
                    task = TestTask(
                        id=f"{chunk.chunk_id}_task_{task_count}",
                        endpoint=endpoint,
                        test_type=test_type,
                        payload=payload,
                        priority=chunk.priority,
                    )
                    engine.add_task(task)
                    task_count += 1

        results = await engine.run_all(_execute_vuln_test)

        vulnerabilities = [
            r for r in results.get("results", {}).values()
            if r.get("vulnerable")
        ]

        return {
            "chunk_id": chunk.chunk_id,
            "endpoints_tested": len(chunk.endpoints),
            "tests_run": task_count,
            "vulnerabilities": vulnerabilities,
        }

    # Run chunks with concurrency limit
    semaphore = asyncio.Semaphore(max_concurrent_chunks)

    async def run_with_semaphore(chunk: ScanChunk):
        async with semaphore:
            result = await process_chunk(chunk)
            coordinator.complete_chunk(chunk.chunk_id, result)
            return result

    activity.heartbeat("Running distributed scan")

    await asyncio.gather(
        *[run_with_semaphore(chunk) for chunk in chunks],
        return_exceptions=True,
    )

    # Get final results
    progress = coordinator.get_progress()
    all_vulns = coordinator.aggregated_results["vulnerabilities"]

    # Notify about findings
    if task_id:
        by_type_summary = "\n".join([
            f"- **{vtype}**: {len(vulns)}"
            for vtype, vulns in coordinator.aggregated_results["by_type"].items()
        ])

        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🌐 Distributed Scan Complete

**Scan Statistics:**
- Endpoints: {len(endpoints)}
- Chunks: {progress['total_chunks']}
- Completed: {progress['completed_chunks']}
- Progress: {progress['progress_percent']:.1f}%

**Vulnerabilities Found:** {len(all_vulns)}

**By Type:**
{by_type_summary if by_type_summary else "No vulnerabilities found"}

Distributed scanning enabled testing at scale with maximum efficiency!""",
            ),
            trace_id=trace_id,
        )

    return {
        "endpoints_tested": len(endpoints),
        "chunks_processed": progress["completed_chunks"],
        "total_vulnerabilities": len(all_vulns),
        "vulnerabilities": all_vulns,
        "by_type": {k: len(v) for k, v in coordinator.aggregated_results["by_type"].items()},
        "progress": progress,
    }


# =============================================================================
# CONTINUOUS TESTING SCHEDULER
# =============================================================================

@activity.defn(name="schedule_continuous_tests_activity")
async def schedule_continuous_tests_activity(
    target_domain: str,
    test_interval_minutes: int,
    endpoints: List[str],
    test_types: List[str],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Schedule continuous testing for ongoing security assessment.

    This activity:
    1. Creates a testing schedule
    2. Determines optimal test intervals
    3. Prioritizes tests based on risk
    4. Returns schedule configuration
    """
    logger.info(f"Scheduling continuous tests for {target_domain}")

    activity.heartbeat("Creating test schedule")

    # Categorize endpoints by risk
    high_risk = []
    medium_risk = []
    low_risk = []

    for endpoint in endpoints:
        endpoint_lower = endpoint.lower()
        if any(p in endpoint_lower for p in ["admin", "auth", "api", "upload", "exec"]):
            high_risk.append(endpoint)
        elif any(p in endpoint_lower for p in ["user", "account", "search", "query"]):
            medium_risk.append(endpoint)
        else:
            low_risk.append(endpoint)

    # Create schedule
    schedule = {
        "target_domain": target_domain,
        "created_at": datetime.utcnow().isoformat(),
        "schedules": [
            {
                "name": "high_risk_scan",
                "endpoints": high_risk,
                "test_types": test_types,
                "interval_minutes": test_interval_minutes,
                "priority": "critical",
            },
            {
                "name": "medium_risk_scan",
                "endpoints": medium_risk,
                "test_types": test_types,
                "interval_minutes": test_interval_minutes * 2,
                "priority": "high",
            },
            {
                "name": "low_risk_scan",
                "endpoints": low_risk,
                "test_types": ["xss", "sqli"],  # Basic tests only
                "interval_minutes": test_interval_minutes * 4,
                "priority": "medium",
            },
            {
                "name": "full_scan",
                "endpoints": endpoints,
                "test_types": test_types,
                "interval_minutes": test_interval_minutes * 24,  # Daily
                "priority": "low",
            },
        ],
        "next_runs": {
            "high_risk_scan": datetime.utcnow().isoformat(),
            "medium_risk_scan": datetime.utcnow().isoformat(),
            "low_risk_scan": datetime.utcnow().isoformat(),
            "full_scan": datetime.utcnow().isoformat(),
        },
    }

    # Notify about schedule
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### ⏰ Continuous Testing Schedule Created

**Target:** `{target_domain}`

**Scheduled Scans:**
- 🔴 **High Risk** ({len(high_risk)} endpoints): Every {test_interval_minutes} min
- 🟠 **Medium Risk** ({len(medium_risk)} endpoints): Every {test_interval_minutes * 2} min
- 🟢 **Low Risk** ({len(low_risk)} endpoints): Every {test_interval_minutes * 4} min
- 🔵 **Full Scan** ({len(endpoints)} endpoints): Daily

Continuous pentesting is now active - security assessment that never sleeps!""",
            ),
            trace_id=trace_id,
        )

    return {
        "target_domain": target_domain,
        "schedule": schedule,
        "endpoint_counts": {
            "high_risk": len(high_risk),
            "medium_risk": len(medium_risk),
            "low_risk": len(low_risk),
            "total": len(endpoints),
        },
    }