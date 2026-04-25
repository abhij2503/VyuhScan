#scanner.py — Core scanning engine for VyuhScan

import socket
import concurrent.futures
import time
from dataclasses import dataclass, field

COMMON_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    2375:  "Docker",
    2376:  "Docker-TLS",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5601:  "Kibana",
    5900:  "VNC",
    5984:  "CouchDB",
    6379:  "Redis",
    7001:  "WebLogic",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "Jupyter",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch-Cluster",
    11211: "Memcached",
    27017: "MongoDB",
}


@dataclass
class PortResult:
    port: int
    state: str
    service: str
    banner: str = ""


@dataclass
class ScanResult:
    target: str
    ip: str
    hostname: str
    scan_time: float
    ports: list[PortResult] = field(default_factory=list)
    error: str | None = None

def resolve_target(target: str) -> tuple[str, str]:
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = target
        return ip, hostname
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve target '{target}': {e}")
    
def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner.splitlines()[0] if banner else ""
    except Exception:
        return ""

def scan_port(ip: str, port: int, timeout: float, grab_banners: bool) -> PortResult:
    service = COMMON_PORTS.get(port, "Unknown")
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            banner = grab_banner(ip, port, timeout) if grab_banners else ""
            return PortResult(port=port, state="open", service=service, banner=banner)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return PortResult(port=port, state="closed", service=service)
    
def run_scan(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 1.0,
    threads: int = 100,
    grab_banners: bool = True,
) -> ScanResult:
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    start = time.time()

    try:
        ip, hostname = resolve_target(target)
    except ValueError as e:
        return ScanResult(
            target=target,
            ip="",
            hostname="",
            scan_time=0.0,
            error=str(e),
        )

    results: list[PortResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout, grab_banners): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.port)

    elapsed = round(time.time() - start, 2)

    return ScanResult(
        target=target,
        ip=ip,
        hostname=hostname,
        scan_time=elapsed,
        ports=results,
    )