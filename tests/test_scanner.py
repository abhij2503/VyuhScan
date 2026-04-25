# tests/test_scanner.py — Unit tests for VyuhScan scanner

import pytest
from unittest.mock import patch, MagicMock
from vyuhscan.scanner import (
    resolve_target,
    scan_port,
    run_scan,
    PortResult,
    COMMON_PORTS,
)


def test_resolve_target_with_ip():
    ip, hostname = resolve_target("127.0.0.1")
    assert ip == "127.0.0.1"


def test_resolve_target_invalid():
    with pytest.raises(ValueError, match="Cannot resolve"):
        resolve_target("this.host.does.not.exist.invalid")


def test_scan_port_open():
    with patch("vyuhscan.scanner.socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        result = scan_port("127.0.0.1", 80, timeout=1.0, grab_banners=False)
        assert result.state == "open"
        assert result.port == 80
        assert result.service == "HTTP"


def test_scan_port_closed():
    with patch(
        "vyuhscan.scanner.socket.create_connection",
        side_effect=ConnectionRefusedError,
    ):
        result = scan_port("127.0.0.1", 9999, timeout=1.0, grab_banners=False)
        assert result.state == "closed"
        assert result.port == 9999


def test_scan_port_unknown_service():
    with patch(
        "vyuhscan.scanner.socket.create_connection",
        side_effect=ConnectionRefusedError,
    ):
        result = scan_port("127.0.0.1", 12345, timeout=1.0, grab_banners=False)
        assert result.service == "Unknown"


def test_run_scan_bad_host():
    result = run_scan("this.host.does.not.exist.invalid", ports=[80])
    assert result.error is not None
    assert "Cannot resolve" in result.error
    assert result.ports == []


def test_run_scan_returns_all_ports():
    ports = [80, 443, 22]
    def fake_scan_port(ip, port, timeout, grab_banners):
        return PortResult(port=port, state="closed", service="Unknown")
    with patch("vyuhscan.scanner.resolve_target", return_value=("1.2.3.4", "fake.host")):
        with patch("vyuhscan.scanner.scan_port", side_effect=fake_scan_port):
            result = run_scan("fake.host", ports=ports)
    assert len(result.ports) == len(ports)


def test_run_scan_sorted_output():
    ports = [443, 22, 80]
    def fake_scan_port(ip, port, timeout, grab_banners):
        return PortResult(port=port, state="open", service="Test")
    with patch("vyuhscan.scanner.resolve_target", return_value=("1.2.3.4", "fake.host")):
        with patch("vyuhscan.scanner.scan_port", side_effect=fake_scan_port):
            result = run_scan("fake.host", ports=ports)
    returned_ports = [p.port for p in result.ports]
    assert returned_ports == sorted(returned_ports)