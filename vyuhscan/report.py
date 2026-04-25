# report.py — Output formatting for VyuhScan

import json
import dataclasses
from datetime import datetime
from .scanner import ScanResult, PortResult


def _green(s: str) -> str:  return f"\033[92m{s}\033[0m"
def _red(s: str) -> str:    return f"\033[91m{s}\033[0m"
def _cyan(s: str) -> str:   return f"\033[96m{s}\033[0m"
def _bold(s: str) -> str:   return f"\033[1m{s}\033[0m"
def _dim(s: str) -> str:    return f"\033[2m{s}\033[0m"
def _yellow(s: str) -> str: return f"\033[93m{s}\033[0m"

BANNER = r"""
 __     __           _     ____                 
 \ \   / /   _ _   _| |__ / ___|  ___ __ _ _ __  
  \ \ / / | | | | | | '_ \\___ \ / __/ _` | '_ \ 
   \ V /| |_| | |_| | | | |___) | (_| (_| | | | |
    \_/  \__, |\__,_|_| |_|____/ \___\__,_|_| |_|
          |___/                                    

  Strategic Network Reconnaissance  |  github.com/abhij2503/vyuhscan
"""


def print_banner() -> None:
    print(_cyan(BANNER))

def print_summary(result: ScanResult, show_closed: bool = False) -> None:
    if result.error:
        print(_red(f"\n[ERROR] {result.error}\n"))
        return

    open_ports = [p for p in result.ports if p.state == "open"]
    closed_ports = [p for p in result.ports if p.state == "closed"]

    print()
    print(_bold("─" * 60))
    print(_bold("  Target   : ") + _cyan(result.target))
    print(_bold("  IP       : ") + result.ip)
    print(_bold("  Hostname : ") + result.hostname)
    print(_bold("  Scanned  : ") + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(_bold("  Duration : ") + f"{result.scan_time}s")
    print(_bold("  Open     : ") + _green(str(len(open_ports))) + f"  /  {len(result.ports)} ports scanned")
    print(_bold("─" * 60))

    if not open_ports:
        print(_yellow("\n  No open ports found.\n"))
    else:
        print()
        print(_bold(f"  {'PORT':<8} {'STATE':<10} {'SERVICE':<14} BANNER"))
        print(_dim("  " + "─" * 56))
        for p in open_ports:
            banner_snippet = (p.banner[:38] + "…") if len(p.banner) > 38 else p.banner
            state_col = _green("open")
            print(f"  {p.port:<8} {state_col:<19} {p.service:<14} {_dim(banner_snippet)}")

    if show_closed and closed_ports:
        print()
        print(_dim(f"  Closed ports ({len(closed_ports)}): " +
                   ", ".join(str(p.port) for p in closed_ports)))

    print(_bold("─" * 60))
    print()

def _to_dict(result: ScanResult) -> dict:
    d = dataclasses.asdict(result)
    d["scanned_at"] = datetime.now().isoformat()
    return d


def save_json(result: ScanResult, path: str, findings: list = None) -> None:
    from .risk import risk_summary_dict
    d = _to_dict(result)
    d["risk_findings"] = risk_summary_dict(findings) if findings else []
    with open(path, "w") as f:
        json.dump(d, f, indent=2)
    print(_green(f"[+] Report saved → {path}"))


def print_json(result: ScanResult, findings: list = None) -> None:
    from .risk import risk_summary_dict
    d = _to_dict(result)
    d["risk_findings"] = risk_summary_dict(findings) if findings else []
    print(json.dumps(d, indent=2))