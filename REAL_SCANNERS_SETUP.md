# Real Security Scanners - Production Setup Guide

## Overview

All mock/simulated scanning activities have been replaced with **real production-ready security tools**. The Red-Cell agent now uses actual vulnerability scanners and reconnaissance tools.

---

## Integrated Tools

### 1. **Nuclei** - Vulnerability Scanner
- **Purpose**: Fast vulnerability scanner using community templates
- **Usage**: Scans for CVEs, misconfigurations, and known vulnerabilities
- **Templates**: 5000+ community templates covering web apps, APIs, networks
- **Output**: JSON format with detailed vulnerability information

### 2. **Nmap** - Network Scanner
- **Purpose**: Port scanning and service detection
- **Usage**: Discovers open ports, services, and versions
- **Features**: Service version detection, OS fingerprinting, NSE scripts
- **Output**: XML format with detailed service information

### 3. **httpx** - HTTP Toolkit
- **Purpose**: Fast HTTP probing and technology detection
- **Usage**: Probes web servers, detects technologies, extracts metadata
- **Features**: Tech detection, status codes, server headers, titles
- **Output**: JSON format with web server details

### 4. **Subfinder** - Subdomain Enumeration
- **Purpose**: Passive subdomain discovery
- **Usage**: Discovers subdomains using multiple sources (APIs, search engines)
- **Features**: Fast, passive, uses 30+ sources
- **Output**: JSON format with discovered subdomains

### 5. **DNS Resolution** - Python Socket
- **Purpose**: Resolve hostnames to IP addresses
- **Usage**: Standard DNS lookups using Python's socket library
- **Features**: Async resolution, error handling
- **Output**: Hostname to IP mapping

---

## Docker Image

The Dockerfile uses **Kali Linux** base image which includes all security tools pre-installed:

```dockerfile
FROM vxcontrol/kali-linux-image:latest
```

### Pre-installed Tools:
- ✅ nmap
- ✅ subfinder
- ✅ nuclei
- ✅ httpx
- ✅ metasploit-framework
- ✅ sqlmap
- ✅ nikto
- ✅ And 20+ more pentesting tools

---

## Real Scanner Implementation

### Nuclei Scanner
```python
@activity.defn(name="run_nuclei_scan_activity")
async def run_nuclei_scan_activity(targets, templates, task_id, trace_id):
    """Run actual nuclei vulnerability scanner."""

    # Create targets file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write('\n'.join(targets))
        targets_file = f.name

    # Run nuclei with real templates
    cmd = [
        "nuclei",
        "-l", targets_file,
        "-t", templates,  # e.g., "cves,vulnerabilities"
        "-json",
        "-o", output_file,
        "-rate-limit", "150",
    ]

    # Execute and parse JSON results
    # Returns: vulnerabilities with severity, CVE IDs, evidence
```

### Nmap Scanner
```python
@activity.defn(name="run_nmap_scan_activity")
async def run_nmap_scan_activity(target, ports, options, task_id, trace_id):
    """Run actual nmap port scan."""

    cmd = [
        "nmap",
        "-p", ports,
        "-sV",  # Service version detection
        "-sC",  # Default scripts
        "--open",
        "-oX", "-",  # XML output
        target
    ]

    # Execute and parse XML results
    # Returns: open ports, services, versions
```

### httpx Probe
```python
@activity.defn(name="run_httpx_probe_activity")
async def run_httpx_probe_activity(hosts, task_id, trace_id):
    """Probe HTTP/HTTPS services using httpx."""

    cmd = [
        "httpx",
        "-l", hosts_file,
        "-json",
        "-tech-detect",  # Detect technologies
        "-server",       # Extract server headers
        "-title",        # Get page titles
        "-rate-limit", "100",
    ]

    # Execute and parse JSON results
    # Returns: URLs, status codes, technologies, servers
```

---

## Testing Against Juice Shop

### Expected Results

When scanning **bkimminich/juice-shop** at `http://example.com:3001/`, you should now see:

#### 1. **Asset Discovery**
- Discovered host: example.com:3001
- Resolved IP address
- Detected web service on port 3001

#### 2. **Technology Detection**
- Node.js/Express
- Angular
- SQLite
- Various npm packages

#### 3. **Vulnerability Findings**

Nuclei should detect multiple vulnerabilities:

**Critical:**
- SQL Injection vulnerabilities
- Authentication bypass
- Admin panel exposure

**High:**
- XSS vulnerabilities
- Insecure direct object references
- Broken access control

**Medium:**
- Information disclosure
- Missing security headers
- Weak password policy

**Low:**
- Directory listing
- Verbose error messages
- Cookie security issues

---

## Build and Run

### 1. Build Docker Image
```bash
cd agents/red-cell
docker build -t red-cell:latest .
```

### 2. Run Container
```bash
docker run -it --rm \
  --name red-cell-worker \
  -e TEMPORAL_ADDRESS="host.docker.internal:7233" \
  -e OPENAI_API_KEY="your-key" \
  -e LITELLM_API_KEY="your-key" \
  -e AGENTEX_BASE_URL="http://host.docker.internal:5003" \
  -e AGENT_API_KEY="your-key" \
  red-cell:latest
```

### 3. Submit Scan Request
```json
{
  "target_scope": {
    "domains": ["example.com:3001"],
    "rules_of_engagement": "Authorized testing of Juice Shop"
  },
  "scan_type": "standard"
}
```

---

## Rate Limiting & Safety

All scanners include rate limiting to avoid overwhelming targets:

- **Nuclei**: 150 requests/second
- **httpx**: 100 requests/second
- **Nmap**: Default timing (polite)
- **Subfinder**: Passive (no rate limit needed)

---

## Troubleshooting

### Issue: "nuclei: command not found"
**Solution**: Ensure Docker image is built from Kali Linux base

### Issue: "Permission denied"
**Solution**: Run container with appropriate network permissions

### Issue: "No vulnerabilities found"
**Solution**:
1. Verify target is accessible from container
2. Check nuclei templates are up to date
3. Ensure target has actual vulnerabilities

### Issue: "Connection timeout"
**Solution**:
1. Check network connectivity
2. Verify target URL is correct
3. Ensure firewall allows outbound connections

---

## Performance Considerations

### Scan Times (Approximate)

- **Subdomain Discovery**: 30-60 seconds per domain
- **Port Scanning**: 1-5 minutes per host (1000 ports)
- **Nuclei Scan**: 2-10 minutes per target (depends on templates)
- **httpx Probe**: 10-30 seconds per 100 hosts
- **Technology Detection**: 10-30 seconds per 100 hosts

### Resource Usage

- **CPU**: Moderate (nuclei and nmap are CPU-intensive)
- **Memory**: 512MB - 2GB depending on scan size
- **Network**: High bandwidth for large scans
- **Disk**: Minimal (temporary files only)

---

## Next Steps

1. **Build the Docker image** with real scanners
2. **Test against Juice Shop** to verify vulnerability detection
3. **Review scan results** in the generated report
4. **Tune rate limits** based on your infrastructure
5. **Add custom nuclei templates** for specific vulnerabilities

---

## Security Notes

⚠️ **Important**:
- Only scan systems you have **explicit authorization** to test
- Respect rate limits to avoid DoS
- Review and approve all exploit attempts
- Maintain audit logs of all scanning activities
- Follow responsible disclosure practices

---

## Support

For issues or questions:
1. Check Docker logs: `docker logs red-cell-worker`
2. Verify tool versions: `docker exec red-cell-worker nuclei -version`
3. Test tools manually: `docker exec -it red-cell-worker bash`
