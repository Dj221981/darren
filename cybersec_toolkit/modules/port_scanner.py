"""
Port Scanner
Fast, multi-threaded TCP port scanner for network reconnaissance and security auditing.
"""

import socket
import concurrent.futures
import time
from dataclasses import dataclass, field
from typing import Optional

# Common ports with service names
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP (submission)",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    2181: "ZooKeeper",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    6443: "Kubernetes API",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9200: "Elasticsearch",
    27017: "MongoDB",
    11211: "Memcached",
}

RISK_PORTS = {
    21: ("Medium", "FTP transmits data in plaintext. Consider SFTP instead."),
    23: ("High", "Telnet is unencrypted. Use SSH instead."),
    135: ("High", "MS-RPC is frequently exploited. Restrict with firewall."),
    139: ("High", "NetBIOS is a common attack vector. Block externally."),
    445: ("High", "SMB vulnerabilities (EternalBlue etc.). Patch and restrict."),
    1433: ("Medium", "MSSQL should not be exposed to the internet."),
    3306: ("Medium", "MySQL should not be exposed to the internet."),
    3389: ("High", "RDP is a common attack target. Use VPN + NLA."),
    4444: ("Critical", "Default Metasploit port — potential backdoor!"),
    5900: ("Medium", "VNC should require strong auth and be behind VPN."),
    6379: ("High", "Redis often has no auth. Restrict with firewall."),
    27017: ("High", "MongoDB often has no auth by default."),
    11211: ("High", "Memcached can be used for DDoS amplification."),
}


@dataclass
class PortResult:
    port: int
    state: str = ""  # "open", "closed", "filtered"
    service: str = ""
    banner: str = ""
    risk_level: str = ""
    risk_note: str = ""
    response_ms: float = 0.0


@dataclass
class ScanResult:
    target: str
    target_ip: str = ""
    scan_start: str = ""
    scan_end: str = ""
    duration_seconds: float = 0.0
    ports_scanned: int = 0
    open_ports: list = field(default_factory=list)
    error: str = ""


def resolve_host(host: str) -> tuple[str, str]:
    """Resolve a hostname to an IP address. Returns (hostname, ip)."""
    try:
        ip = socket.gethostbyname(host)
        return host, ip
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve host '{host}': {e}")


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner from an open port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Send a generic HTTP request for web ports, else just read
            if port in (80, 8080, 8000, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(256)
            return data.decode("utf-8", errors="replace").strip()[:120]
    except Exception:
        return ""


def scan_port(host: str, port: int, timeout: float = 1.0, grab_banners: bool = False) -> PortResult:
    """Scan a single TCP port and return its state."""
    start = time.monotonic()
    result = PortResult(
        port=port,
        service=COMMON_PORTS.get(port, "Unknown"),
    )

    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.monotonic() - start) * 1000
            result.state = "open"
            result.response_ms = round(elapsed, 1)

            if port in RISK_PORTS:
                result.risk_level, result.risk_note = RISK_PORTS[port]

            if grab_banners:
                result.banner = grab_banner(host, port, timeout)

    except (socket.timeout, ConnectionRefusedError):
        result.state = "closed"
    except OSError:
        result.state = "filtered"

    return result


def scan(
    target: str,
    ports: Optional[list[int]] = None,
    port_range: Optional[tuple[int, int]] = None,
    timeout: float = 1.0,
    max_workers: int = 100,
    grab_banners: bool = False,
) -> ScanResult:
    """
    Perform a multi-threaded TCP port scan against the target.

    Args:
        target: Hostname or IP address to scan
        ports: Specific list of ports to scan
        port_range: Tuple of (start_port, end_port), inclusive
        timeout: Connection timeout per port in seconds
        max_workers: Number of concurrent threads
        grab_banners: Whether to attempt banner grabbing on open ports

    Returns:
        ScanResult with all open port details
    """
    result = ScanResult(
        target=target,
        scan_start=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )

    try:
        _, ip = resolve_host(target)
        result.target_ip = ip
    except ValueError as e:
        result.error = str(e)
        return result

    # Determine which ports to scan
    if ports:
        scan_ports = ports
    elif port_range:
        start, end = port_range
        scan_ports = list(range(max(1, start), min(65535, end) + 1))
    else:
        scan_ports = list(COMMON_PORTS.keys())

    result.ports_scanned = len(scan_ports)
    start_time = time.monotonic()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout, grab_banners): port
            for port in scan_ports
        }
        for future in concurrent.futures.as_completed(futures):
            port_result = future.result()
            if port_result.state == "open":
                result.open_ports.append(port_result)

    result.open_ports.sort(key=lambda r: r.port)
    result.duration_seconds = round(time.monotonic() - start_time, 2)
    result.scan_end = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    return result
