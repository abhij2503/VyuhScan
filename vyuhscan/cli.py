# cli.py — Command-line interface for VyuhScan
import os
import sys

# Enable ANSI colour codes in Windows terminal
if sys.platform == "win32":
    os.system("")

import argparse
import sys
from .scanner import run_scan, COMMON_PORTS
from .report import print_banner, print_summary, save_json, print_json
from .risk import score_scan, print_risk_report
import re

def validate_target(target: str) -> bool:
    # Allow hostnames and IP addresses only
    pattern = r'^[a-zA-Z0-9.\-]+$'
    return bool(re.match(pattern, target))

def parse_ports(port_str: str) -> list[int]:
    if port_str == "common":
        return list(COMMON_PORTS.keys())
    ports: list[int] = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vyuhscan",
        description="VyuhScan — Strategic network reconnaissance with built-in risk scoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vyuhscan scanme.nmap.org
  vyuhscan 192.168.1.1 -p 22,80,443
  vyuhscan 10.0.0.1 -p 1-1024 --threads 200
  vyuhscan example.com --json -o report.json
  vyuhscan example.com --no-risk
  vyuhscan example.com --no-banners --show-closed
        """,
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument("-p", "--ports", default="common", metavar="PORTS",
        help='Ports: "common", "80,443", or "1-1024" (default: common)')
    parser.add_argument("-t", "--timeout", type=float, default=1.0, metavar="SEC",
        help="Per-port timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=100, metavar="N",
        help="Concurrent threads (default: 100)")
    parser.add_argument("--no-banners", action="store_true",
        help="Skip banner grabbing (faster)")
    parser.add_argument("--show-closed", action="store_true",
        help="Include closed ports in output")
    parser.add_argument("--no-risk", action="store_true",
        help="Skip risk assessment")
    parser.add_argument("--json", action="store_true", dest="json_out",
        help="Output JSON to stdout")
    parser.add_argument("-o", "--output", metavar="FILE",
        help="Save full JSON report to FILE")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.json_out:
        print_banner()

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print(f"[!] Invalid port specification: {args.ports}", file=sys.stderr)
        sys.exit(1)
    
    if not validate_target(args.target):
        print(f"[!] Invalid target: '{args.target}'. Only hostnames and IP addresses are allowed.", file=sys.stderr)
        sys.exit(1)

    if not args.json_out:
        print(f"[*] Scanning {args.target} across {len(ports)} ports ...\n")

    result = run_scan(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
        grab_banners=not args.no_banners,
    )

    findings = [] if args.no_risk else score_scan(result)

    if args.json_out:
        print_json(result, findings)
    else:
        print_summary(result, show_closed=args.show_closed)
        if not args.no_risk:
            print_risk_report(findings)

    if args.output:
        save_json(result, args.output, findings)


if __name__ == "__main__":
    main()