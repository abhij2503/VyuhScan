# risk.py — Port risk scoring engine for VyuhScan

from dataclasses import dataclass
from .scanner import PortResult, ScanResult

RISK_DB: dict[int, tuple[str, str]] = {
    21:    ("HIGH",     "FTP transmits credentials in plaintext. Use SFTP instead."),
    22:    ("INFO",     "SSH is expected. Verify key-based auth is enforced and root login is disabled."),
    23:    ("CRITICAL", "Telnet transmits all data including passwords in plaintext. Disable immediately."),
    25:    ("MEDIUM",   "SMTP open to the internet may enable spam relay. Verify auth is required."),
    53:    ("MEDIUM",   "DNS exposed externally. Check for zone transfer vulnerability (AXFR)."),
    80:    ("LOW",      "HTTP (unencrypted). Ensure sensitive content redirects to HTTPS."),
    110:   ("HIGH",     "POP3 may transmit credentials in plaintext. Use POP3S (port 995) instead."),
    143:   ("HIGH",     "IMAP may transmit credentials in plaintext. Use IMAPS (port 993) instead."),
    443:   ("INFO",     "HTTPS. Verify TLS version (TLS 1.2+ required) and certificate validity."),
    445:   ("CRITICAL", "SMB exposed externally. High risk of lateral movement and ransomware (EternalBlue)."),
    1433:  ("CRITICAL", "MSSQL database exposed externally. Should never be internet-facing."),
    2375:  ("CRITICAL", "Docker daemon exposed. Gives full control of the host. Disable immediately."),
    2376:  ("HIGH",     "Docker daemon TLS port exposed. Verify client certificate auth is enforced."),
    3306:  ("CRITICAL", "MySQL database exposed externally. Should never be internet-facing."),
    3389:  ("CRITICAL", "RDP exposed externally. Prime target for brute-force and BlueKeep exploits."),
    5432:  ("CRITICAL", "PostgreSQL database exposed externally. Should never be internet-facing."),
    5601:  ("HIGH",     "Kibana exposed externally. May expose sensitive log data without auth."),
    5900:  ("HIGH",     "VNC exposed externally. Often weak passwords, full desktop access."),
    5984:  ("CRITICAL", "CouchDB has no auth by default. Exposed instances lead to data loss."),
    6379:  ("CRITICAL", "Redis has no auth by default. Exposed instances are trivially exploitable."),
    7001:  ("CRITICAL", "WebLogic exposed. Frequent target for RCE exploits."),
    8080:  ("LOW",      "HTTP alternative port. Often a dev/staging server — verify intended exposure."),
    8443:  ("LOW",      "HTTPS alternative port. Often a dev/staging server — verify intended exposure."),
    8888:  ("HIGH",     "Jupyter Notebook exposed. Allows arbitrary code execution with no auth by default."),
    9200:  ("CRITICAL", "Elasticsearch exposed. No auth by default — immediate data exposure risk."),
    9300:  ("CRITICAL", "Elasticsearch cluster port exposed. Should never be internet-facing."),
    11211: ("CRITICAL", "Memcached exposed. No auth, used in DDoS amplification attacks."),
    27017: ("CRITICAL", "MongoDB has no auth by default. Exposed instances lead to immediate data loss."),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SEVERITY_COLOURS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[96m",
    "INFO":     "\033[92m",
}
RESET = "\033[0m"


@dataclass
class RiskFinding:
    port: int
    service: str
    severity: str
    reason: str
    banner: str = ""

def score_port(port_result: PortResult) -> RiskFinding | None:
    if port_result.state != "open":
        return None

    entry = RISK_DB.get(port_result.port)
    if not entry:
        return RiskFinding(
            port=port_result.port,
            service=port_result.service,
            severity="LOW",
            reason="Unknown service on non-standard port. Verify this is intentional.",
            banner=port_result.banner,
        )

    severity, reason = entry
    return RiskFinding(
        port=port_result.port,
        service=port_result.service,
        severity=severity,
        reason=reason,
        banner=port_result.banner,
    )


def score_scan(result: ScanResult) -> list[RiskFinding]:
    findings = []
    for port in result.ports:
        finding = score_port(port)
        if finding:
            findings.append(finding)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings


def print_risk_report(findings: list[RiskFinding]) -> None:
    bold = lambda s: f"\033[1m{s}\033[0m"
    dim  = lambda s: f"\033[2m{s}\033[0m"

    print()
    print(bold("─" * 60))
    print(bold("  RISK ASSESSMENT"))
    print(bold("─" * 60))

    if not findings:
        print("\033[92m  No open ports found — nothing to assess.\033[0m")
        print(bold("─" * 60))
        return

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary_parts = []
    for sev, count in counts.items():
        if count:
            colour = SEVERITY_COLOURS[sev]
            summary_parts.append(f"{colour}{count} {sev}{RESET}")
    print("  " + "  |  ".join(summary_parts))
    print()

    for f in findings:
        colour = SEVERITY_COLOURS.get(f.severity, "")
        print(f"  {colour}[{f.severity}]{RESET}  Port {bold(str(f.port))} / {f.service}")
        print(f"  {dim('↳')}  {f.reason}")
        if f.banner:
            print(f"  {dim('Banner:')} {dim(f.banner[:60])}")
        print()

    print(bold("─" * 60))


def risk_summary_dict(findings: list[RiskFinding]) -> list:
    return [
        {
            "port": f.port,
            "service": f.service,
            "severity": f.severity,
            "reason": f.reason,
            "banner": f.banner,
        }
        for f in findings
    ]