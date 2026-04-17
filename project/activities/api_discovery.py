"""
API Discovery Activities for Major-Project AI Pentester.

This module provides comprehensive API discovery capabilities:
- OpenAPI/Swagger endpoint detection
- GraphQL introspection
- REST API endpoint enumeration
- API versioning detection
- Authentication mechanism identification
- Rate limiting detection
"""
import asyncio
import json
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from openai import AsyncOpenAI
from temporalio import activity

from agentex.lib.utils.logging import make_logger
from agentex.lib import adk
from agentex.types.text_content import TextContent
from agentex.types.tool_request_content import ToolRequestContent
from agentex.types.tool_response_content import ToolResponseContent

logger = make_logger(__name__)


# Common API documentation paths
OPENAPI_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api-docs.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/openapi.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/docs/openapi.json",
    "/.well-known/openapi.json",
]

GRAPHQL_PATHS = [
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/gql",
]

API_VERSION_PATTERNS = [
    r"/v\d+/",
    r"/api/v\d+/",
    r"/api/\d+\.\d+/",
]


async def call_llm_for_api_analysis(prompt: str, system_prompt: str) -> str:
    """Call LLM for API analysis."""
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
        temperature=0.3,
        max_tokens=2000,
    )

    return response.choices[0].message.content


async def http_request(url: str, method: str = "GET", headers: Optional[Dict] = None,
                       body: Optional[str] = None, timeout: int = 10) -> Dict[str, Any]:
    """Make an HTTP request using httpx."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
            if method == "GET":
                response = await client.get(url, headers=headers)
            elif method == "POST":
                response = await client.post(url, headers=headers, content=body)
            elif method == "OPTIONS":
                response = await client.options(url, headers=headers)
            else:
                response = await client.request(method, url, headers=headers, content=body)

            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:10000],  # Limit body size
                "url": str(response.url),
            }
    except Exception as e:
        return {
            "error": str(e),
            "status_code": 0,
        }


@activity.defn(name="discover_openapi_endpoints_activity")
async def discover_openapi_endpoints_activity(
    base_url: str,
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Discover OpenAPI/Swagger documentation endpoints.

    This activity:
    1. Probes common OpenAPI documentation paths
    2. Parses discovered specifications
    3. Extracts all API endpoints
    4. Identifies authentication requirements
    """
    logger.info(f"Discovering OpenAPI endpoints for {base_url}")

    activity.heartbeat("Probing OpenAPI endpoints")

    discovered_specs = []
    all_endpoints = []
    auth_schemes = []

    # Normalize base URL
    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    # Probe common OpenAPI paths
    for path in OPENAPI_PATHS:
        url = urljoin(base_url, path)

        try:
            result = await http_request(url)

            if result.get("status_code") == 200:
                body = result.get("body", "")

                # Try to parse as JSON
                try:
                    spec = json.loads(body)

                    # Check if it's a valid OpenAPI spec
                    if "openapi" in spec or "swagger" in spec:
                        discovered_specs.append({
                            "url": url,
                            "version": spec.get("openapi") or spec.get("swagger"),
                            "title": spec.get("info", {}).get("title", "Unknown"),
                        })

                        # Extract endpoints
                        paths = spec.get("paths", {})
                        for endpoint, methods in paths.items():
                            for method, details in methods.items():
                                if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                                    all_endpoints.append({
                                        "path": endpoint,
                                        "method": method.upper(),
                                        "summary": details.get("summary", ""),
                                        "parameters": [p.get("name") for p in details.get("parameters", [])],
                                        "security": details.get("security", []),
                                    })

                        # Extract security schemes
                        security_schemes = spec.get("components", {}).get("securitySchemes", {})
                        if not security_schemes:
                            security_schemes = spec.get("securityDefinitions", {})

                        for name, scheme in security_schemes.items():
                            auth_schemes.append({
                                "name": name,
                                "type": scheme.get("type"),
                                "scheme": scheme.get("scheme"),
                                "in": scheme.get("in"),
                            })

                        logger.info(f"Found OpenAPI spec at {url} with {len(all_endpoints)} endpoints")

                except json.JSONDecodeError:
                    # Try YAML parsing
                    try:
                        import yaml
                        spec = yaml.safe_load(body)
                        if spec and ("openapi" in spec or "swagger" in spec):
                            discovered_specs.append({
                                "url": url,
                                "version": spec.get("openapi") or spec.get("swagger"),
                                "title": spec.get("info", {}).get("title", "Unknown"),
                            })
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"Failed to probe {url}: {e}")

    # Notify about discovery
    if task_id and discovered_specs:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 📚 OpenAPI Specifications Discovered

**Specifications Found:** {len(discovered_specs)}
**Total Endpoints:** {len(all_endpoints)}
**Auth Schemes:** {len(auth_schemes)}

**Discovered Specs:**
{chr(10).join([f"- `{s['url']}` - {s['title']} (v{s['version']})" for s in discovered_specs])}

**Sample Endpoints:**
{chr(10).join([f"- `{e['method']} {e['path']}`" for e in all_endpoints[:10]])}
""",
            ),
            trace_id=trace_id,
        )

    return {
        "base_url": base_url,
        "discovered_specs": discovered_specs,
        "endpoints": all_endpoints,
        "auth_schemes": auth_schemes,
        "total_endpoints": len(all_endpoints),
    }


@activity.defn(name="discover_graphql_endpoints_activity")
async def discover_graphql_endpoints_activity(
    base_url: str,
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Discover and introspect GraphQL endpoints.

    This activity:
    1. Probes common GraphQL paths
    2. Performs introspection queries
    3. Extracts schema information
    4. Identifies queries, mutations, and subscriptions
    """
    logger.info(f"Discovering GraphQL endpoints for {base_url}")

    activity.heartbeat("Probing GraphQL endpoints")

    discovered_endpoints = []
    schema_info = []

    # Normalize base URL
    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    # GraphQL introspection query
    introspection_query = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                name
                kind
                fields {
                    name
                    args { name type { name } }
                    type { name kind }
                }
            }
        }
    }
    """

    # Probe common GraphQL paths
    for path in GRAPHQL_PATHS:
        url = urljoin(base_url, path)

        try:
            # Try POST with introspection query
            result = await http_request(
                url,
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"query": introspection_query}),
            )

            if result.get("status_code") == 200:
                body = result.get("body", "")

                try:
                    response = json.loads(body)

                    if "data" in response and "__schema" in response.get("data", {}):
                        schema = response["data"]["__schema"]

                        discovered_endpoints.append({
                            "url": url,
                            "introspection_enabled": True,
                        })

                        # Extract types
                        types = schema.get("types", [])
                        queries = []
                        mutations = []

                        query_type_name = schema.get("queryType", {}).get("name", "Query")
                        mutation_type_name = schema.get("mutationType", {}).get("name", "Mutation")

                        for t in types:
                            if t.get("name") == query_type_name:
                                queries = [f.get("name") for f in t.get("fields", [])]
                            elif t.get("name") == mutation_type_name:
                                mutations = [f.get("name") for f in t.get("fields", [])]

                        schema_info.append({
                            "url": url,
                            "queries": queries,
                            "mutations": mutations,
                            "total_types": len(types),
                        })

                        logger.info(f"Found GraphQL endpoint at {url} with {len(queries)} queries, {len(mutations)} mutations")

                except json.JSONDecodeError:
                    pass

            # Also try GET for GraphiQL interface
            get_result = await http_request(url)
            if get_result.get("status_code") == 200:
                body = get_result.get("body", "")
                if "graphiql" in body.lower() or "graphql" in body.lower():
                    if not any(e["url"] == url for e in discovered_endpoints):
                        discovered_endpoints.append({
                            "url": url,
                            "introspection_enabled": False,
                            "graphiql_detected": True,
                        })

        except Exception as e:
            logger.debug(f"Failed to probe {url}: {e}")

    # Notify about discovery
    if task_id and discovered_endpoints:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🔮 GraphQL Endpoints Discovered

**Endpoints Found:** {len(discovered_endpoints)}

**Discovered Endpoints:**
{chr(10).join([f"- `{e['url']}` {'(Introspection Enabled ⚠️)' if e.get('introspection_enabled') else ''}" for e in discovered_endpoints])}

**Schema Information:**
{chr(10).join([f"- `{s['url']}`: {len(s['queries'])} queries, {len(s['mutations'])} mutations" for s in schema_info])}
""",
            ),
            trace_id=trace_id,
        )

    return {
        "base_url": base_url,
        "discovered_endpoints": discovered_endpoints,
        "schema_info": schema_info,
        "total_endpoints": len(discovered_endpoints),
    }


@activity.defn(name="enumerate_api_endpoints_activity")
async def enumerate_api_endpoints_activity(
    base_url: str,
    known_endpoints: List[str],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Enumerate API endpoints through crawling and fuzzing.

    This activity:
    1. Crawls the application for API calls
    2. Fuzzes common API patterns
    3. Detects API versioning
    4. Identifies hidden endpoints
    """
    logger.info(f"Enumerating API endpoints for {base_url}")

    activity.heartbeat("Enumerating API endpoints")

    discovered_endpoints = set(known_endpoints)
    api_versions = set()

    # Normalize base URL
    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    # Common API endpoint patterns to fuzz
    api_patterns = [
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/v3",
        "/rest",
        "/rest/v1",
        "/v1",
        "/v2",
        "/v3",
        "/api/users",
        "/api/auth",
        "/api/login",
        "/api/register",
        "/api/profile",
        "/api/settings",
        "/api/admin",
        "/api/health",
        "/api/status",
        "/api/config",
        "/api/data",
        "/api/search",
        "/api/export",
        "/api/import",
        "/api/upload",
        "/api/download",
        "/api/webhook",
        "/api/callback",
        "/api/internal",
        "/api/private",
        "/api/public",
    ]

    # Probe API patterns
    for pattern in api_patterns:
        url = urljoin(base_url, pattern)

        try:
            result = await http_request(url)
            status = result.get("status_code", 0)

            # Consider 200, 401, 403 as valid endpoints
            if status in [200, 201, 401, 403, 405]:
                discovered_endpoints.add(pattern)

                # Check for version patterns
                for version_pattern in API_VERSION_PATTERNS:
                    if re.search(version_pattern, pattern):
                        match = re.search(r'v(\d+)', pattern)
                        if match:
                            api_versions.add(f"v{match.group(1)}")

        except Exception as e:
            logger.debug(f"Failed to probe {url}: {e}")

    # Use katana for deeper crawling if available
    try:
        import tempfile

        output_file = tempfile.mktemp(suffix='.json')
        cmd = [
            "katana",
            "-u", base_url,
            "-d", "2",
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
        await asyncio.wait_for(process.communicate(), timeout=60)

        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            result = json.loads(line)
                            endpoint = result.get('request', {}).get('endpoint', '')
                            if endpoint and '/api' in endpoint.lower():
                                parsed = urlparse(endpoint)
                                discovered_endpoints.add(parsed.path)
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            pass

    except Exception as e:
        logger.debug(f"Katana crawling failed: {e}")

    # Analyze endpoints with AI
    if discovered_endpoints:
        analysis_prompt = f"""Analyze these API endpoints and identify:
1. Potential security-sensitive endpoints
2. Admin/privileged endpoints
3. Authentication endpoints
4. Data export/import endpoints
5. Potential IDOR vulnerabilities

Endpoints:
{chr(10).join(list(discovered_endpoints)[:50])}

Return a JSON object with categorized endpoints and security notes."""

        try:
            analysis = await call_llm_for_api_analysis(
                analysis_prompt,
                "You are an API security expert analyzing endpoints for vulnerabilities."
            )

            # Parse analysis
            try:
                analysis_data = json.loads(analysis)
            except json.JSONDecodeError:
                analysis_data = {"raw_analysis": analysis}

        except Exception:
            analysis_data = {}
    else:
        analysis_data = {}

    # Notify about discovery
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🔍 API Endpoint Enumeration Complete

**Endpoints Discovered:** {len(discovered_endpoints)}
**API Versions Detected:** {', '.join(api_versions) if api_versions else 'None'}

**Sample Endpoints:**
{chr(10).join([f"- `{e}`" for e in list(discovered_endpoints)[:15]])}
""",
            ),
            trace_id=trace_id,
        )

    return {
        "base_url": base_url,
        "discovered_endpoints": list(discovered_endpoints),
        "api_versions": list(api_versions),
        "total_endpoints": len(discovered_endpoints),
        "analysis": analysis_data,
    }


@activity.defn(name="detect_api_authentication_activity")
async def detect_api_authentication_activity(
    base_url: str,
    endpoints: List[str],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Detect authentication mechanisms used by APIs.

    This activity:
    1. Probes endpoints for auth requirements
    2. Identifies auth types (JWT, API Key, OAuth, Basic)
    3. Detects auth bypass opportunities
    4. Checks for rate limiting
    """
    logger.info(f"Detecting API authentication for {base_url}")

    activity.heartbeat("Detecting API authentication")

    auth_findings = []
    rate_limit_info = []

    # Normalize base URL
    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    # Test endpoints for auth requirements
    for endpoint in endpoints[:20]:  # Limit to 20 endpoints
        url = urljoin(base_url, endpoint)

        try:
            # Test without auth
            result = await http_request(url)
            status = result.get("status_code", 0)
            headers = result.get("headers", {})

            auth_info = {
                "endpoint": endpoint,
                "requires_auth": status in [401, 403],
                "auth_type": None,
                "rate_limited": False,
            }

            # Check WWW-Authenticate header
            www_auth = headers.get("www-authenticate", "").lower()
            if "bearer" in www_auth:
                auth_info["auth_type"] = "Bearer/JWT"
            elif "basic" in www_auth:
                auth_info["auth_type"] = "Basic"
            elif "digest" in www_auth:
                auth_info["auth_type"] = "Digest"

            # Check for API key requirements
            body = result.get("body", "").lower()
            if "api key" in body or "apikey" in body or "x-api-key" in body:
                auth_info["auth_type"] = "API Key"

            # Check for OAuth
            if "oauth" in body or "authorization_code" in body:
                auth_info["auth_type"] = "OAuth"

            # Check rate limiting headers
            rate_limit_headers = [
                "x-ratelimit-limit",
                "x-rate-limit-limit",
                "ratelimit-limit",
                "x-ratelimit-remaining",
                "retry-after",
            ]

            for rl_header in rate_limit_headers:
                if rl_header in [h.lower() for h in headers.keys()]:
                    auth_info["rate_limited"] = True
                    rate_limit_info.append({
                        "endpoint": endpoint,
                        "header": rl_header,
                        "value": headers.get(rl_header),
                    })
                    break

            auth_findings.append(auth_info)

        except Exception as e:
            logger.debug(f"Failed to test auth for {url}: {e}")

    # Summarize findings
    requires_auth_count = sum(1 for f in auth_findings if f["requires_auth"])
    auth_types = set(f["auth_type"] for f in auth_findings if f["auth_type"])
    rate_limited_count = sum(1 for f in auth_findings if f["rate_limited"])

    # Notify about findings
    if task_id:
        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🔐 API Authentication Analysis

**Endpoints Tested:** {len(auth_findings)}
**Require Authentication:** {requires_auth_count}
**Rate Limited:** {rate_limited_count}

**Auth Types Detected:**
{chr(10).join([f"- {t}" for t in auth_types]) if auth_types else "- None detected"}

**Unprotected Endpoints:**
{chr(10).join([f"- `{f['endpoint']}`" for f in auth_findings if not f['requires_auth']][:10])}
""",
            ),
            trace_id=trace_id,
        )

    return {
        "base_url": base_url,
        "auth_findings": auth_findings,
        "rate_limit_info": rate_limit_info,
        "summary": {
            "total_tested": len(auth_findings),
            "requires_auth": requires_auth_count,
            "unprotected": len(auth_findings) - requires_auth_count,
            "auth_types": list(auth_types),
            "rate_limited": rate_limited_count,
        },
    }


@activity.defn(name="analyze_api_security_activity")
async def analyze_api_security_activity(
    base_url: str,
    openapi_spec: Optional[Dict[str, Any]],
    endpoints: List[str],
    task_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    """
    Perform comprehensive API security analysis using AI.

    This activity:
    1. Analyzes API structure for security issues
    2. Identifies potential vulnerabilities
    3. Checks for common API security misconfigurations
    4. Provides remediation recommendations
    """
    logger.info(f"Analyzing API security for {base_url}")

    activity.heartbeat("Analyzing API security")

    # Build context for AI analysis
    context = {
        "base_url": base_url,
        "endpoints": endpoints[:50],
        "has_openapi_spec": openapi_spec is not None,
    }

    if openapi_spec:
        context["openapi_version"] = openapi_spec.get("openapi") or openapi_spec.get("swagger")
        context["security_schemes"] = list(openapi_spec.get("components", {}).get("securitySchemes", {}).keys())

    analysis_prompt = f"""Analyze this API for security vulnerabilities:

Context:
{json.dumps(context, indent=2)}

Endpoints:
{chr(10).join(endpoints[:30])}

Identify:
1. **OWASP API Top 10 vulnerabilities** that may be present
2. **Authentication/Authorization issues**
3. **Data exposure risks**
4. **Rate limiting concerns**
5. **Input validation issues**
6. **Injection vulnerabilities**

For each finding, provide:
- Vulnerability type
- Affected endpoint(s)
- Severity (critical/high/medium/low)
- Description
- Remediation

Return as JSON:
{{
    "findings": [
        {{
            "type": "vulnerability type",
            "endpoints": ["affected endpoints"],
            "severity": "high",
            "description": "description",
            "remediation": "how to fix"
        }}
    ],
    "overall_risk": "high/medium/low",
    "recommendations": ["list of recommendations"]
}}
"""

    try:
        analysis = await call_llm_for_api_analysis(
            analysis_prompt,
            """You are an API security expert specializing in OWASP API Security Top 10.
Analyze APIs for vulnerabilities and provide actionable remediation guidance.
Be thorough but avoid false positives."""
        )

        # Parse analysis
        try:
            # Extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', analysis)
            if json_match:
                analysis_data = json.loads(json_match.group())
            else:
                analysis_data = {"raw_analysis": analysis}
        except json.JSONDecodeError:
            analysis_data = {"raw_analysis": analysis}

    except Exception as e:
        logger.error(f"API security analysis failed: {e}")
        analysis_data = {"error": str(e)}

    # Notify about analysis
    if task_id:
        findings = analysis_data.get("findings", [])
        overall_risk = analysis_data.get("overall_risk", "unknown")

        findings_summary = ""
        for f in findings[:5]:
            findings_summary += f"\n- **{f.get('type', 'Unknown')}** ({f.get('severity', 'unknown').upper()}): {f.get('description', '')[:100]}..."

        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🛡️ API Security Analysis Complete

**Overall Risk Level:** {overall_risk.upper()}
**Findings:** {len(findings)}

**Top Findings:**
{findings_summary if findings_summary else "No significant findings"}

**Recommendations:**
{chr(10).join([f"- {r}" for r in analysis_data.get('recommendations', [])[:5]])}
""",
            ),
            trace_id=trace_id,
        )

    return {
        "base_url": base_url,
        "analysis": analysis_data,
        "findings_count": len(analysis_data.get("findings", [])),
        "overall_risk": analysis_data.get("overall_risk", "unknown"),
    }