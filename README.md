# VyuhScan

![CI](https://github.com/abhij2503/vyuhscan/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

VyuhScan takes a host and scans it against a curated list of ports that are commonly
misconfigured or critical from a security standpoint. For each open port it identifies 
the service running, grabs the banner, and assigns a risk level so you know what 
actually needs attention.

Most scanners just tell you what's open. VyuhScan tells you what's open and why you 
should care. A Redis port open to the internet hits differently than port 80 — VyuhScan 
makes that distinction automatic.

Built in pure Python with no external dependencies, it's lightweight enough to run inside 
Lambda functions, Docker containers, or CI pipelines where installing Nmap isn't practical.

## Features

- Scans a host against a curated list of commonly misconfigured and high-risk ports
- Concurrent scanning — connects to all ports simultaneously instead of one by one
- Grabs service banners to identify what is actually responding on each port
- Assigns a risk level (CRITICAL / HIGH / MEDIUM / LOW / INFO) to each open port
- Exports results as JSON for scripting, pipelines, or further analysis
- Zero external dependencies — pure Python stdlib

## Installation

```bash
git clone https://github.com/abhij2503/vyuhscan.git
cd vyuhscan
python -m pip install -e .
```

Requires Python 3.10 or higher. No external dependencies.

## Usage

```bash
# Basic scan
vyuhscan scanme.nmap.org

# Scan specific ports
vyuhscan 192.168.1.1 -p 22,80,443

# Scan a port range
vyuhscan 10.0.0.1 -p 1-1024 --threads 200

# Save results to JSON
vyuhscan example.com --json -o report.json

# Skip risk assessment
vyuhscan example.com --no-risk

# Faster scan, show closed ports too
vyuhscan example.com --no-banners --show-closed
```

## Example Output
vyuhscan scanme.nmap.org
────────────────────────────────────────────────────────────
Target   : scanme.nmap.org
IP       : 45.33.32.156
Hostname : scanme.nmap.org
Scanned  : 2026-04-24 18:03:33
Duration : 1.14s
Open     : 2  /  27 ports scanned
────────────────────────────────────────────────────────────
PORT     STATE      SERVICE        BANNER
────────────────────────────────────────────────────────
22       open       SSH
80       open       HTTP           HTTP/1.1 200 OK
────────────────────────────────────────────────────────────
RISK ASSESSMENT
────────────────────────────────────────────────────────────
1 LOW  |  1 INFO
[LOW]  Port 80 / HTTP
↳  HTTP (unencrypted). Ensure sensitive content redirects to HTTPS.
[INFO]  Port 22 / SSH
↳  SSH is expected. Verify key-based auth is enforced and root login is disabled.
────────────────────────────────────────────────────────────

## Options

| Flag | Default | Description |
|---|---|---|
| `-p`, `--ports` | `common` | `common`, `80,443`, or `1-1024` |
| `-t`, `--timeout` | `1.0` | Per-port timeout in seconds |
| `--threads` | `100` | Concurrent threads |
| `--no-banners` | off | Skip banner grabbing (faster) |
| `--show-closed` | off | Include closed ports in output |
| `--no-risk` | off | Skip risk assessment |
| `--json` | off | Output JSON to stdout |
| `-o`, `--output` | — | Save JSON report to file |

## Running Tests

```bash
python -m pip install pytest
python -m pytest -v
```

16 tests covering port scanning, banner grabbing, and risk scoring.

## Legal Notice
Only scan systems you own or have **explicit written permission** to test.
Unauthorized port scanning may be illegal in your jurisdiction.

## License
MIT © [Abhi Jayaswal](https://github.com/abhij2503)