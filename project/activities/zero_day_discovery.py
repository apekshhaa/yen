"""
Zero-Day Discovery through Creative AI Reasoning.

This module implements advanced AI-driven vulnerability discovery that goes
beyond known patterns to discover novel vulnerabilities through:

1. Behavioral Anomaly Detection - Detecting unusual application responses
2. Semantic Code Analysis - Understanding application logic to find flaws
3. Mutation-Based Fuzzing - Intelligent payload evolution
4. Cross-Context Reasoning - Finding vulnerabilities across different contexts
5. Novel Attack Vector Generation - Creating new attack patterns

This is the core of "zero-day-like" discovery - finding vulnerabilities
that scanners and static patterns would miss.
"""
import asyncio
import hashlib
import json
import os
import re
import statistics
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from openai import AsyncOpenAI
from temporalio import activity

from agentex.lib.utils.logging import make_logger
from agentex.lib import adk
from agentex.types.text_content import TextContent

logger = make_logger(__name__)


async def call_llm(prompt: str, system_prompt: str, temperature: float = 0.8, max_tokens: int = 3000, timeout: float = 60.0) -> str:
    """Call LLM for creative reasoning with timeout handling."""
    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    model = os.environ.get("OPENAI_MODEL", "gpt-4")

    if not api_key:
        raise ValueError("OPENAI_API_KEY not set")

    client = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=timeout,
    )

    try:
        response = await asyncio.wait_for(
            client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                temperature=temperature,
                max_tokens=max_tokens,
            ),
            timeout=timeout,
        )
        return response.choices[0].message.content
    except asyncio.TimeoutError:
        logger.warning(f"LLM call timed out after {timeout}s")
        return "{}"
    except asyncio.CancelledError:
        logger.warning("LLM call was cancelled")
        raise
    except Exception as e:
        logger.warning(f"LLM call failed: {e}")
        return "{}"


# =============================================================================
# BEHAVIORAL ANOMALY DETECTION
# =============================================================================

class BehavioralAnalyzer:
    """Analyzes application behavior to detect anomalies that may indicate vulnerabilities."""

    def __init__(self):
        self.baseline_responses: Dict[str, List[Dict[str, Any]]] = {}
        self.anomalies: List[Dict[str, Any]] = []

    def compute_response_signature(self, response: Dict[str, Any]) -> str:
        """Compute a signature for a response to detect changes."""
        sig_data = {
            "status": response.get("status_code", 0),
            "length_bucket": response.get("content_length", 0) // 100,  # Bucket by 100 bytes
            "content_type": response.get("content_type", ""),
            "has_error": any(e in str(response.get("body", "")).lower()
                           for e in ["error", "exception", "warning", "failed"]),
        }
        return hashlib.md5(json.dumps(sig_data, sort_keys=True).encode()).hexdigest()[:8]

    def add_baseline(self, endpoint: str, response: Dict[str, Any]):
        """Add a response to the baseline for an endpoint."""
        if endpoint not in self.baseline_responses:
            self.baseline_responses[endpoint] = []
        self.baseline_responses[endpoint].append({
            "signature": self.compute_response_signature(response),
            "status": response.get("status_code"),
            "length": response.get("content_length", 0),
            "timestamp": datetime.utcnow().isoformat(),
        })

    def detect_anomaly(self, endpoint: str, response: Dict[str, Any], payload: str) -> Optional[Dict[str, Any]]:
        """Detect if a response is anomalous compared to baseline."""
        if endpoint not in self.baseline_responses or len(self.baseline_responses[endpoint]) < 3:
            return None

        baseline = self.baseline_responses[endpoint]
        current_sig = self.compute_response_signature(response)
        current_length = response.get("content_length", 0)
        current_status = response.get("status_code", 0)

        # Check signature deviation
        baseline_sigs = [b["signature"] for b in baseline]
        if current_sig not in baseline_sigs:
            # New signature - potential anomaly
            baseline_lengths = [b["length"] for b in baseline]
            avg_length = statistics.mean(baseline_lengths) if baseline_lengths else 0
            length_deviation = abs(current_length - avg_length) / max(avg_length, 1)

            if length_deviation > 0.3 or current_status >= 500:
                anomaly = {
                    "type": "behavioral_anomaly",
                    "endpoint": endpoint,
                    "payload": payload,
                    "deviation": {
                        "signature_new": True,
                        "length_deviation": length_deviation,
                        "status_code": current_status,
                        "baseline_avg_length": avg_length,
                        "current_length": current_length,
                    },
                    "severity": "high" if current_status >= 500 else "medium",
                    "timestamp": datetime.utcnow().isoformat(),
                }
                self.anomalies.append(anomaly)
                return anomaly

        return None


_behavioral_analyzer = BehavioralAnalyzer()


@activity.defn(name="behavioral_anomaly_detection_activity")
async def behavioral_anomaly_detection_activity(
    target_url: str,
    endpoints: List[str],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Detect behavioral anomalies that may indicate vulnerabilities.

    This activity:
    1. Establishes baseline behavior for endpoints
    2. Sends various inputs and monitors for deviations
    3. Uses AI to analyze anomalies for potential vulnerabilities
    """
    logger.info(f"Running behavioral anomaly detection on {len(endpoints)} endpoints")

    activity.heartbeat("Starting behavioral analysis")

    anomalies_found = []

    # Behavioral test inputs - designed to trigger edge cases
    test_inputs = [
        "",  # Empty
        "null",
        "undefined",
        "NaN",
        "-1",
        "0",
        "999999999999",
        "true",
        "false",
        "[]",
        "{}",
        '{"$gt":""}',  # NoSQL injection
        "{{7*7}}",  # Template injection
        "${7*7}",
        "%00",  # Null byte
        "\n\r",
        "A" * 10000,  # Long string
        "../" * 10,
        "<!--",
        "<%",
    ]

    for endpoint in endpoints[:20]:  # Limit endpoints
        try:
            activity.heartbeat(f"Analyzing {endpoint}")

            # First, establish baseline with normal request
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)

            if not params:
                continue

            # Get baseline responses
            for _ in range(3):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "curl", "-s", "-w", "\n%{http_code}\n%{size_download}", "-m", "5", endpoint,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await proc.communicate()
                    output = stdout.decode(errors='ignore')
                    lines = output.strip().split('\n')

                    if len(lines) >= 2:
                        status = int(lines[-2]) if lines[-2].isdigit() else 0
                        length = int(lines[-1]) if lines[-1].isdigit() else 0
                        body = '\n'.join(lines[:-2])

                        _behavioral_analyzer.add_baseline(endpoint, {
                            "status_code": status,
                            "content_length": length,
                            "body": body[:500],
                        })
                except Exception:
                    continue

            # Test with anomaly-inducing inputs
            for param_name in list(params.keys())[:3]:  # Limit params
                for test_input in test_inputs:
                    try:
                        # Inject test input
                        test_params = params.copy()
                        test_params[param_name] = [test_input]
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))

                        proc = await asyncio.create_subprocess_exec(
                            "curl", "-s", "-w", "\n%{http_code}\n%{size_download}", "-m", "5", test_url,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        stdout, _ = await proc.communicate()
                        output = stdout.decode(errors='ignore')
                        lines = output.strip().split('\n')

                        if len(lines) >= 2:
                            status = int(lines[-2]) if lines[-2].isdigit() else 0
                            length = int(lines[-1]) if lines[-1].isdigit() else 0
                            body = '\n'.join(lines[:-2])

                            response = {
                                "status_code": status,
                                "content_length": length,
                                "body": body[:500],
                            }

                            anomaly = _behavioral_analyzer.detect_anomaly(endpoint, response, test_input)
                            if anomaly:
                                anomaly["parameter"] = param_name
                                anomalies_found.append(anomaly)

                    except Exception:
                        continue

        except Exception as e:
            logger.debug(f"Behavioral analysis failed for {endpoint}: {e}")

    # Use AI to analyze anomalies (with timeout protection)
    if anomalies_found:
        activity.heartbeat("Analyzing anomalies with AI")

        analysis_prompt = f"""Analyze these behavioral anomalies detected during security testing:

{json.dumps(anomalies_found[:5], indent=2)}

For each anomaly, determine:
1. Is this likely a security vulnerability?
2. What type of vulnerability might this indicate?
3. What additional tests should be performed?
4. What is the potential impact?

Return JSON:
{{
  "analyzed_anomalies": [
    {{
      "endpoint": "...",
      "likely_vulnerability": true/false,
      "vulnerability_type": "SQLi/XSS/etc or null",
      "confidence": 0.0-1.0,
      "reasoning": "...",
      "recommended_tests": ["..."],
      "potential_impact": "..."
    }}
  ]
}}"""

        try:
            ai_response = await call_llm(
                analysis_prompt,
                "You are a security expert analyzing application behavior anomalies to identify potential vulnerabilities.",
                temperature=0.3,
                timeout=45.0,  # Shorter timeout for this call
            )

            # Parse AI analysis
            json_match = re.search(r'\{[\s\S]*\}', ai_response)
            if json_match:
                ai_analysis = json.loads(json_match.group())

                # Merge AI analysis with anomalies
                for analyzed in ai_analysis.get("analyzed_anomalies", []):
                    if analyzed.get("likely_vulnerability"):
                        for anomaly in anomalies_found:
                            if anomaly.get("endpoint") == analyzed.get("endpoint"):
                                anomaly["ai_analysis"] = analyzed
                                anomaly["severity"] = "critical" if analyzed.get("confidence", 0) > 0.8 else "high"

        except Exception as e:
            logger.warning(f"AI analysis failed: {e}")

    # Notify about findings
    if task_id and anomalies_found:
        high_confidence = [a for a in anomalies_found if a.get("ai_analysis", {}).get("confidence", 0) > 0.7]
        medium_confidence = [a for a in anomalies_found if 0.3 <= a.get("ai_analysis", {}).get("confidence", 0) <= 0.7]

        # Build anomaly details
        if high_confidence:
            high_conf_list = "\n".join([
                f"- 🔴 **{a.get('endpoint', 'unknown')[:50]}** - {a.get('ai_analysis', {}).get('vulnerability_type', 'Unknown')} (Confidence: {a.get('ai_analysis', {}).get('confidence', 0):.0%})"
                for a in high_confidence[:5]
            ])
        else:
            high_conf_list = "  *None with high confidence*"

        # Show sample anomalies even if not high confidence
        sample_anomalies = "\n".join([
            f"- `{a.get('endpoint', 'unknown')[:40]}` - Status: {a.get('deviation', {}).get('status_code', 'N/A')}, Length deviation: {a.get('deviation', {}).get('length_deviation', 0):.1%}"
            for a in anomalies_found[:8]
        ])

        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🔬 Behavioral Anomaly Detection Results

**Anomalies Detected:** {len(anomalies_found)}
**High Confidence Vulnerabilities:** {len(high_confidence)}
**Medium Confidence:** {len(medium_confidence)}

#### High Confidence Findings:
{high_conf_list}

#### Sample Anomalies Detected:
{sample_anomalies}
{f'*...and {len(anomalies_found) - 8} more anomalies*' if len(anomalies_found) > 8 else ''}

These anomalies indicate unusual application behavior that may reveal vulnerabilities. Further investigation recommended.""",
            ),
            trace_id=trace_id,
        )

    return {
        "endpoints_analyzed": len(endpoints),
        "anomalies_found": len(anomalies_found),
        "anomalies": anomalies_found,
        "high_confidence_count": len([a for a in anomalies_found if a.get("ai_analysis", {}).get("confidence", 0) > 0.7]),
    }


# =============================================================================
# SEMANTIC VULNERABILITY REASONING
# =============================================================================

SEMANTIC_REASONING_PROMPT = """You are a world-class security researcher performing semantic analysis of application behavior to discover novel vulnerabilities.

## Application Context
{context}

## Observed Behaviors
{behaviors}

## Your Task
Think deeply about this application's behavior and identify potential vulnerabilities that:
1. Are NOT covered by standard vulnerability scanners
2. Arise from business logic flaws
3. Result from unexpected state transitions
4. Emerge from race conditions or timing issues
5. Come from trust boundary violations

## Reasoning Process
1. **Understand the Application**: What is this application trying to do?
2. **Identify Trust Boundaries**: Where does the application trust user input?
3. **Find State Transitions**: What states can the application be in?
4. **Discover Edge Cases**: What happens in unusual scenarios?
5. **Chain Behaviors**: Can multiple behaviors be combined for exploitation?

## Output Format
Return a JSON object with your findings:
```json
{{
  "application_understanding": "Brief description of what the app does",
  "trust_boundaries": ["List of identified trust boundaries"],
  "potential_vulnerabilities": [
    {{
      "name": "Descriptive name",
      "type": "business_logic|race_condition|state_manipulation|trust_violation|other",
      "description": "Detailed description",
      "exploitation_scenario": "How an attacker would exploit this",
      "impact": "What damage could be done",
      "confidence": 0.0-1.0,
      "test_methodology": "How to test for this vulnerability",
      "proof_of_concept_outline": "High-level PoC steps"
    }}
  ],
  "recommended_deep_tests": ["List of specific tests to perform"]
}}
```

Think creatively - real attackers don't follow checklists."""


@activity.defn(name="semantic_vulnerability_reasoning_activity")
async def semantic_vulnerability_reasoning_activity(
    target_url: str,
    discovered_endpoints: List[str],
    technologies: List[str],
    observed_behaviors: List[Dict[str, Any]],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Use AI semantic reasoning to discover novel vulnerabilities.

    This activity:
    1. Analyzes application structure and behavior
    2. Reasons about business logic and trust boundaries
    3. Identifies potential vulnerabilities beyond standard patterns
    4. Generates novel test cases
    """
    logger.info(f"Running semantic vulnerability reasoning for {target_url}")

    activity.heartbeat("Performing semantic analysis")

    # Build context
    context = f"""
Target: {target_url}
Technologies: {', '.join(technologies) if technologies else 'Unknown'}
Endpoints Discovered: {len(discovered_endpoints)}
Sample Endpoints:
{chr(10).join(discovered_endpoints[:20])}
"""

    behaviors = json.dumps(observed_behaviors[:20], indent=2) if observed_behaviors else "No behaviors observed yet"

    prompt = SEMANTIC_REASONING_PROMPT.format(
        context=context,
        behaviors=behaviors,
    )

    try:
        response = await call_llm(
            prompt,
            "You are an elite security researcher who thinks like an attacker. You find vulnerabilities that others miss by understanding application logic deeply.",
            temperature=0.8,  # Higher for creativity
            max_tokens=4000,
        )

        # Parse response
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            analysis = json.loads(json_match.group())
        else:
            analysis = {"error": "Failed to parse AI response"}

        # Extract high-confidence findings
        potential_vulns = analysis.get("potential_vulnerabilities", [])
        high_confidence = [v for v in potential_vulns if v.get("confidence", 0) > 0.6]

        # Notify about findings
        if task_id and high_confidence:
            vuln_list = "\n".join([
                f"- **{v['name']}** ({v['type']}) - Confidence: {v.get('confidence', 0):.0%}\n  {v['description'][:100]}..."
                for v in high_confidence[:5]
            ])

            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content=f"""### 🧠 Semantic Vulnerability Analysis

**Application Understanding:** {analysis.get('application_understanding', 'Unknown')[:200]}

**Trust Boundaries Identified:** {len(analysis.get('trust_boundaries', []))}

**Potential Novel Vulnerabilities:** {len(high_confidence)}

{vuln_list}

**Recommended Deep Tests:**
{chr(10).join([f"- {t}" for t in analysis.get('recommended_deep_tests', [])[:5]])}

These findings represent potential zero-day-like vulnerabilities discovered through semantic reasoning.""",
                ),
                trace_id=trace_id,
            )

        return {
            "target_url": target_url,
            "analysis": analysis,
            "potential_vulnerabilities": potential_vulns,
            "high_confidence_count": len(high_confidence),
            "recommended_tests": analysis.get("recommended_deep_tests", []),
        }

    except Exception as e:
        logger.error(f"Semantic reasoning failed: {e}")
        return {
            "target_url": target_url,
            "error": str(e),
            "potential_vulnerabilities": [],
        }


# =============================================================================
# INTELLIGENT MUTATION FUZZING
# =============================================================================

class MutationFuzzer:
    """Intelligent fuzzer that evolves payloads based on feedback."""

    def __init__(self):
        self.successful_mutations: List[Dict[str, Any]] = []
        self.mutation_history: Dict[str, List[str]] = {}
        self.fitness_scores: Dict[str, float] = {}

    def calculate_fitness(self, payload: str, response: Dict[str, Any]) -> float:
        """Calculate fitness score for a payload based on response."""
        score = 0.0

        body = str(response.get("body", "")).lower()
        status = response.get("status_code", 200)

        # Error indicators increase fitness
        error_indicators = ["error", "exception", "warning", "syntax", "unexpected", "invalid"]
        for indicator in error_indicators:
            if indicator in body:
                score += 0.2

        # Server errors are interesting
        if status >= 500:
            score += 0.5
        elif status >= 400:
            score += 0.1

        # Reflection of payload is interesting
        if payload.lower() in body:
            score += 0.3

        # Long response might indicate data leakage
        if response.get("content_length", 0) > 10000:
            score += 0.1

        return min(score, 1.0)

    def mutate_payload(self, payload: str, mutation_type: str = "random") -> str:
        """Apply mutation to a payload."""
        mutations = {
            "case": lambda p: p.swapcase(),
            "double_encode": lambda p: p.replace("%", "%25"),
            "null_byte": lambda p: p + "%00",
            "newline": lambda p: p + "%0a",
            "unicode": lambda p: p.replace("'", "ʼ").replace('"', "ʺ"),
            "comment": lambda p: p + "/**/",
            "concat": lambda p: p[:len(p)//2] + "/**/" + p[len(p)//2:],
            "whitespace": lambda p: p.replace(" ", "%20%20"),
            "reverse": lambda p: p[::-1],
            "duplicate": lambda p: p + p,
        }

        if mutation_type == "random":
            import random
            mutation_type = random.choice(list(mutations.keys()))

        mutator = mutations.get(mutation_type, lambda p: p)
        return mutator(payload)

    def evolve_population(self, payloads: List[Tuple[str, float]], top_n: int = 5) -> List[str]:
        """Evolve payload population based on fitness scores."""
        # Sort by fitness
        sorted_payloads = sorted(payloads, key=lambda x: x[1], reverse=True)

        # Keep top performers
        survivors = [p[0] for p in sorted_payloads[:top_n]]

        # Generate mutations of survivors
        evolved = []
        mutation_types = ["case", "double_encode", "null_byte", "unicode", "comment", "concat"]

        for survivor in survivors:
            evolved.append(survivor)  # Keep original
            for mut_type in mutation_types[:3]:  # Apply 3 mutations each
                evolved.append(self.mutate_payload(survivor, mut_type))

        return evolved


_mutation_fuzzer = MutationFuzzer()


@activity.defn(name="intelligent_mutation_fuzzing_activity")
async def intelligent_mutation_fuzzing_activity(
    target_url: str,
    parameter: str,
    initial_payloads: List[str],
    generations: int,
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Perform intelligent mutation-based fuzzing that evolves payloads.

    This activity:
    1. Starts with seed payloads
    2. Tests and scores each payload
    3. Evolves successful payloads through mutation
    4. Discovers novel attack vectors through evolution
    """
    logger.info(f"Running intelligent mutation fuzzing on {target_url} param={parameter}")

    activity.heartbeat("Starting mutation fuzzing")

    from urllib.parse import quote, urlparse, parse_qs, urlencode, urlunparse

    current_population = initial_payloads.copy()
    all_findings = []
    best_payloads = []

    for gen in range(generations):
        activity.heartbeat(f"Generation {gen + 1}/{generations}")

        generation_results = []

        for payload in current_population[:30]:  # Limit per generation
            try:
                # Test payload
                encoded = quote(payload, safe='')
                parsed = urlparse(target_url)
                params = parse_qs(parsed.query)
                params[parameter] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-w", "\n%{http_code}\n%{size_download}", "-m", "5", test_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                output = stdout.decode(errors='ignore')
                lines = output.strip().split('\n')

                if len(lines) >= 2:
                    status = int(lines[-2]) if lines[-2].isdigit() else 200
                    length = int(lines[-1]) if lines[-1].isdigit() else 0
                    body = '\n'.join(lines[:-2])

                    response = {
                        "status_code": status,
                        "content_length": length,
                        "body": body[:1000],
                    }

                    fitness = _mutation_fuzzer.calculate_fitness(payload, response)
                    generation_results.append((payload, fitness))

                    # High fitness indicates potential vulnerability
                    if fitness > 0.5:
                        finding = {
                            "payload": payload,
                            "fitness": fitness,
                            "generation": gen + 1,
                            "response_status": status,
                            "response_length": length,
                            "indicators": [],
                        }

                        # Identify what made this interesting
                        if status >= 500:
                            finding["indicators"].append("server_error")
                        if payload.lower() in body.lower():
                            finding["indicators"].append("reflection")
                        if any(e in body.lower() for e in ["error", "exception", "syntax"]):
                            finding["indicators"].append("error_message")

                        all_findings.append(finding)
                        best_payloads.append(payload)

            except Exception:
                continue

        # Evolve population for next generation
        if generation_results:
            current_population = _mutation_fuzzer.evolve_population(generation_results)

    # Analyze findings with AI
    if all_findings:
        activity.heartbeat("Analyzing fuzzing results with AI")

        analysis_prompt = f"""Analyze these fuzzing results to identify potential vulnerabilities:

Target: {target_url}
Parameter: {parameter}

High-Fitness Payloads Found:
{json.dumps(all_findings[:15], indent=2)}

For each finding:
1. What vulnerability type does this indicate?
2. How confident are you this is exploitable?
3. What is the recommended exploitation approach?

Return JSON:
{{
  "vulnerability_findings": [
    {{
      "payload": "...",
      "vulnerability_type": "...",
      "confidence": 0.0-1.0,
      "exploitation_approach": "...",
      "severity": "critical|high|medium|low"
    }}
  ],
  "novel_attack_vectors": ["List of novel attack patterns discovered"]
}}"""

        try:
            ai_response = await call_llm(
                analysis_prompt,
                "You are a security expert analyzing fuzzing results to identify exploitable vulnerabilities.",
                temperature=0.3,
            )

            json_match = re.search(r'\{[\s\S]*\}', ai_response)
            if json_match:
                ai_analysis = json.loads(json_match.group())
            else:
                ai_analysis = {}
        except Exception:
            ai_analysis = {}
    else:
        ai_analysis = {}

    # Notify about findings
    if task_id and all_findings:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🧬 Intelligent Mutation Fuzzing Results

**Target:** `{target_url}`
**Parameter:** `{parameter}`
**Generations:** {generations}
**High-Fitness Payloads:** {len(all_findings)}

**Top Evolved Payloads:**
{chr(10).join([f"- `{f['payload'][:50]}...` (Fitness: {f['fitness']:.2f}, Gen: {f['generation']})" for f in sorted(all_findings, key=lambda x: x['fitness'], reverse=True)[:5]])}

**Novel Attack Vectors Discovered:**
{chr(10).join([f"- {v}" for v in ai_analysis.get('novel_attack_vectors', [])[:5]])}

These payloads evolved through mutation to maximize vulnerability indicators.""",
            ),
            trace_id=trace_id,
        )

    return {
        "target_url": target_url,
        "parameter": parameter,
        "generations": generations,
        "findings": all_findings,
        "best_payloads": best_payloads[:20],
        "ai_analysis": ai_analysis,
        "total_findings": len(all_findings),
    }


# =============================================================================
# NOVEL ATTACK VECTOR GENERATION
# =============================================================================

NOVEL_ATTACK_PROMPT = """You are an elite security researcher tasked with generating NOVEL attack vectors that have never been seen before.

## Target Context
{context}

## Known Vulnerability Types Already Tested
{tested_types}

## Your Mission
Generate completely NEW attack vectors that:
1. Combine multiple vulnerability classes in unexpected ways
2. Exploit application-specific logic
3. Use novel encoding or obfuscation techniques
4. Target emerging technologies or frameworks
5. Exploit timing, race conditions, or state issues

## Creativity Guidelines
- Think about what a scanner would NEVER test
- Consider the specific technology stack
- Look for logic flaws, not just injection points
- Think about multi-step attacks
- Consider client-side and server-side interactions

## Output Format
Return a JSON array of novel attack vectors:
```json
[
  {{
    "name": "Descriptive name for this attack",
    "category": "logic|timing|encoding|chained|state|other",
    "description": "What this attack does",
    "novelty_factor": "Why this is novel/unique",
    "payload_template": "The actual payload or attack pattern",
    "target_parameter": "Which parameter/endpoint to target",
    "prerequisites": ["What must be true for this to work"],
    "expected_behavior": "What indicates success",
    "potential_impact": "What damage could be done",
    "detection_difficulty": "easy|medium|hard"
  }}
]
```

Be creative and think outside the box. Real zero-days come from novel thinking."""


@activity.defn(name="generate_novel_attack_vectors_activity")
async def generate_novel_attack_vectors_activity(
    target_url: str,
    technologies: List[str],
    endpoints: List[str],
    tested_vuln_types: List[str],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Generate novel attack vectors using creative AI reasoning.

    This activity:
    1. Analyzes target context
    2. Considers what has already been tested
    3. Generates completely novel attack patterns
    4. Provides exploitation guidance
    """
    logger.info(f"Generating novel attack vectors for {target_url}")

    activity.heartbeat("Generating novel attacks with AI")

    context = f"""
Target URL: {target_url}
Technologies: {', '.join(technologies) if technologies else 'Unknown'}
Endpoints ({len(endpoints)}):
{chr(10).join(endpoints[:15])}
"""

    tested = ', '.join(tested_vuln_types) if tested_vuln_types else "SQLi, XSS, SSRF, Path Traversal, Command Injection"

    prompt = NOVEL_ATTACK_PROMPT.format(
        context=context,
        tested_types=tested,
    )

    try:
        response = await call_llm(
            prompt,
            "You are a creative security researcher who discovers zero-day vulnerabilities by thinking differently than others.",
            temperature=0.9,  # High creativity
            max_tokens=4000,
        )

        # Parse response
        json_match = re.search(r'\[[\s\S]*\]', response)
        if json_match:
            novel_attacks = json.loads(json_match.group())
        else:
            novel_attacks = []

        # Notify about generated attacks
        if task_id and novel_attacks:
            attack_list = "\n".join([
                f"- **{a['name']}** ({a['category']})\n  {a['description'][:100]}...\n  Novelty: {a.get('novelty_factor', 'N/A')[:80]}"
                for a in novel_attacks[:5]
            ])

            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content=f"""### 💡 Novel Attack Vectors Generated

**Target:** `{target_url}`
**Novel Attacks Generated:** {len(novel_attacks)}

{attack_list}

These are creative attack patterns designed to discover zero-day-like vulnerabilities.""",
                ),
                trace_id=trace_id,
            )

        return {
            "target_url": target_url,
            "novel_attacks": novel_attacks,
            "total_generated": len(novel_attacks),
            "categories": list(set(a.get("category", "other") for a in novel_attacks)),
        }

    except Exception as e:
        logger.error(f"Novel attack generation failed: {e}")
        return {
            "target_url": target_url,
            "error": str(e),
            "novel_attacks": [],
        }


@activity.defn(name="execute_novel_attack_activity")
async def execute_novel_attack_activity(
    target_url: str,
    attack: Dict[str, Any],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Execute a novel attack vector and analyze results.

    This activity:
    1. Prepares the attack based on the generated pattern
    2. Executes the attack safely
    3. Analyzes the response for success indicators
    4. Reports findings
    """
    logger.info(f"Executing novel attack: {attack.get('name', 'Unknown')}")

    activity.heartbeat(f"Executing: {attack.get('name', 'Unknown')}")

    from urllib.parse import quote

    try:
        payload = attack.get("payload_template", "")
        target_param = attack.get("target_parameter", "")
        expected_behavior = attack.get("expected_behavior", "")

        # Build test URL
        if target_param and "?" in target_url:
            test_url = f"{target_url}&{target_param}={quote(payload, safe='')}"
        elif target_param:
            test_url = f"{target_url}?{target_param}={quote(payload, safe='')}"
        else:
            test_url = target_url

        # Execute attack
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "-i", "-m", "10", test_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        response = stdout.decode(errors='ignore')

        # Analyze response
        success_indicators = []

        # Check for expected behavior
        if expected_behavior:
            expected_lower = expected_behavior.lower()
            response_lower = response.lower()

            # Look for keywords from expected behavior
            keywords = re.findall(r'\b\w+\b', expected_lower)
            for keyword in keywords:
                if len(keyword) > 3 and keyword in response_lower:
                    success_indicators.append(f"Found expected keyword: {keyword}")

        # Check for error indicators
        error_patterns = ["error", "exception", "warning", "syntax", "unexpected", "failed"]
        for pattern in error_patterns:
            if pattern in response.lower():
                success_indicators.append(f"Error indicator: {pattern}")

        # Check for payload reflection
        if payload and payload[:20].lower() in response.lower():
            success_indicators.append("Payload reflected in response")

        # Determine if attack was successful
        success = len(success_indicators) >= 2

        result = {
            "attack_name": attack.get("name", "Unknown"),
            "attack_category": attack.get("category", "unknown"),
            "payload": payload,
            "test_url": test_url[:200],
            "success": success,
            "success_indicators": success_indicators,
            "response_length": len(response),
            "response_sample": response[:500] if success else response[:200],
        }

        # Notify about successful attacks
        if task_id and success:
            await adk.messages.create(
                task_id=task_id,
                content=TextContent(
                    author="agent",
                    content=f"""### 🎯 Novel Attack Success!

**Attack:** {attack.get('name', 'Unknown')}
**Category:** {attack.get('category', 'unknown')}
**Payload:** `{payload[:100]}...`

**Success Indicators:**
{chr(10).join([f"- {i}" for i in success_indicators])}

**Potential Impact:** {attack.get('potential_impact', 'Unknown')}

This is a potential zero-day-like finding discovered through creative AI reasoning!""",
                ),
                trace_id=trace_id,
            )

        return result

    except Exception as e:
        logger.error(f"Novel attack execution failed: {e}")
        return {
            "attack_name": attack.get("name", "Unknown"),
            "error": str(e),
            "success": False,
        }