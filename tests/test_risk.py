# tests/test_risk.py — Unit tests for VyuhScan risk scoring

import pytest
from vyuhscan.scanner import PortResult, ScanResult
from vyuhscan.risk import score_port, score_scan, SEVERITY_ORDER


def test_critical_port_flagged():
    port = PortResult(port=23, state="open", service="Telnet", banner="")
    finding = score_port(port)
    assert finding is not None
    assert finding.severity == "CRITICAL"


def test_closed_port_not_scored():
    port = PortResult(port=23, state="closed", service="Telnet", banner="")
    assert score_port(port) is None


def test_known_safe_port_info():
    port = PortResult(port=22, state="open", service="SSH", banner="")
    finding = score_port(port)
    assert finding is not None
    assert finding.severity == "INFO"


def test_unknown_port_gets_low():
    port = PortResult(port=55555, state="open", service="Unknown", banner="")
    finding = score_port(port)
    assert finding is not None
    assert finding.severity == "LOW"


def test_finding_includes_reason():
    port = PortResult(port=3389, state="open", service="RDP", banner="")
    finding = score_port(port)
    assert finding.reason != ""


def test_scan_sorted_by_severity():
    ports = [
        PortResult(port=22, state="open", service="SSH", banner=""),
        PortResult(port=23, state="open", service="Telnet", banner=""),
        PortResult(port=80, state="open", service="HTTP", banner=""),
    ]
    result = ScanResult(target="test", ip="1.2.3.4", hostname="test",
                        scan_time=0.1, ports=ports)
    findings = score_scan(result)
    orders = [SEVERITY_ORDER[f.severity] for f in findings]
    assert orders == sorted(orders)


def test_empty_scan_no_findings():
    result = ScanResult(target="test", ip="1.2.3.4", hostname="test",
                        scan_time=0.1, ports=[
        PortResult(port=22, state="closed", service="SSH", banner="")
    ])
    assert score_scan(result) == []


def test_multiple_critical_all_returned():
    ports = [
        PortResult(port=23, state="open", service="Telnet", banner=""),
        PortResult(port=3389, state="open", service="RDP", banner=""),
        PortResult(port=6379, state="open", service="Redis", banner=""),
    ]
    result = ScanResult(target="test", ip="1.2.3.4", hostname="test",
                        scan_time=0.1, ports=ports)
    findings = score_scan(result)
    assert len(findings) == 3
    assert all(f.severity == "CRITICAL" for f in findings)