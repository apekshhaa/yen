#!/usr/bin/env python3
"""Quick test script to verify nuclei scanning works."""
import asyncio
import subprocess
import tempfile
from pathlib import Path

async def test_nuclei_scan():
    target = "http://juice-shop.default.svc.cluster.local:3000"

    print(f"Testing nuclei scan against: {target}")

    # Check if nuclei is installed
    result = subprocess.run(["which", "nuclei"], capture_output=True)
    if result.returncode != 0:
        print("ERROR: nuclei not found!")
        return
    print(f"Nuclei found at: {result.stdout.decode().strip()}")

    # Check nuclei version
    result = subprocess.run(["nuclei", "-version"], capture_output=True)
    print(f"Nuclei version: {result.stdout.decode().strip() or result.stderr.decode().strip()}")

    # Check templates
    template_dirs = [
        "/root/nuclei-templates",
        "/root/.local/nuclei-templates",
        Path.home() / "nuclei-templates",
        Path.home() / ".local" / "nuclei-templates",
    ]

    for tdir in template_dirs:
        if Path(tdir).exists():
            print(f"Templates found at: {tdir}")
            # Count templates
            http_count = len(list(Path(tdir).glob("http/**/*.yaml"))) if (Path(tdir) / "http").exists() else 0
            print(f"  HTTP templates: {http_count}")
            break
    else:
        print("WARNING: No templates found in expected locations")

    # Test connectivity
    print(f"\nTesting connectivity to {target}...")
    result = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "5", target], capture_output=True)
    http_code = result.stdout.decode().strip()
    if http_code == "200":
        print(f"SUCCESS: Target is reachable (HTTP {http_code})")
    else:
        print(f"WARNING: Target returned HTTP {http_code} (stderr: {result.stderr.decode()})")

    # Run quick nuclei scan
    print(f"\nRunning nuclei scan (this may take a minute)...")
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(target)
        targets_file = f.name

    output_file = tempfile.mktemp(suffix='.json')

    cmd = [
        "nuclei",
        "-l", targets_file,
        "-severity", "critical,high,medium,low,info",
        "-json",
        "-o", output_file,
        "-rate-limit", "100",
        "-timeout", "10",
    ]

    print(f"Command: {' '.join(cmd)}")

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    print(f"\nNuclei exit code: {process.returncode}")
    if stderr:
        print(f"Nuclei stderr (first 500 chars): {stderr.decode()[:500]}")

    # Check results
    if Path(output_file).exists():
        with open(output_file, 'r') as f:
            lines = f.readlines()
        print(f"\nVulnerabilities found: {len(lines)}")
        for line in lines[:10]:  # Show first 10
            import json
            try:
                vuln = json.loads(line)
                print(f"  - [{vuln.get('info', {}).get('severity', 'unknown')}] {vuln.get('info', {}).get('name', 'Unknown')}")
            except:
                pass
    else:
        print("\nNo output file created - nuclei may have failed")

    # Cleanup
    Path(targets_file).unlink(missing_ok=True)
    Path(output_file).unlink(missing_ok=True)

if __name__ == "__main__":
    asyncio.run(test_nuclei_scan())
