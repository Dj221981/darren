"""
Network Tools
DNS lookup, IP geolocation, SSL certificate inspection, and network utilities.
Uses only the Python standard library.
"""

import socket
import ssl
import json
import urllib.request
import urllib.error
import time
from datetime import datetime, timezone
from typing import Optional


def dns_lookup(hostname: str) -> dict:
    """
    Perform forward and reverse DNS lookups for a hostname or IP.
    Returns all associated IP addresses and reverse PTR records.
    """
    result = {
        "query": hostname,
        "forward_records": [],
        "reverse_records": [],
        "error": None,
    }

    # Forward lookup: hostname → IP(s)
    try:
        info = socket.getaddrinfo(hostname, None)
        seen = set()
        for item in info:
            ip = item[4][0]
            if ip not in seen:
                seen.add(ip)
                result["forward_records"].append(ip)
    except socket.gaierror as e:
        result["error"] = f"Forward lookup failed: {e}"
        return result

    # Reverse lookup: IP → hostname
    for ip in result["forward_records"]:
        try:
            ptr = socket.gethostbyaddr(ip)
            result["reverse_records"].append({"ip": ip, "hostname": ptr[0]})
        except socket.herror:
            result["reverse_records"].append({"ip": ip, "hostname": "No PTR record"})

    return result


def get_ssl_certificate_info(hostname: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Retrieve and inspect the SSL/TLS certificate of a host.
    Reports expiry, issuer, subject, and security notes.
    """
    result = {
        "host": hostname,
        "port": port,
        "certificate": {},
        "warnings": [],
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=hostname) as ssl_sock:
                cert = ssl_sock.getpeercert()
                cipher = ssl_sock.cipher()
                tls_version = ssl_sock.version()

        # Parse subject and issuer
        def parse_dn(dn_tuple):
            return {k: v for item in dn_tuple for k, v in item}

        subject = parse_dn(cert.get("subject", ()))
        issuer = parse_dn(cert.get("issuer", ()))

        # Parse expiry dates
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_until_expiry = (not_after - now).days

        result["certificate"] = {
            "subject": subject,
            "issuer": issuer,
            "common_name": subject.get("commonName", ""),
            "san": cert.get("subjectAltName", []),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_until_expiry": days_until_expiry,
            "serial_number": cert.get("serialNumber", ""),
            "tls_version": tls_version,
            "cipher_suite": cipher[0] if cipher else "",
            "is_expired": days_until_expiry < 0,
        }

        # Security warnings
        if days_until_expiry < 0:
            result["warnings"].append("CRITICAL: Certificate has EXPIRED!")
        elif days_until_expiry < 14:
            result["warnings"].append(f"WARNING: Certificate expires in {days_until_expiry} days — renew immediately!")
        elif days_until_expiry < 30:
            result["warnings"].append(f"NOTICE: Certificate expires in {days_until_expiry} days")

        if tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
            result["warnings"].append(f"SECURITY: {tls_version} is insecure. Server should use TLS 1.2+")

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {e}"
        result["warnings"].append("CRITICAL: Certificate is untrusted or invalid!")
    except socket.timeout:
        result["error"] = f"Connection timed out after {timeout}s"
    except ConnectionRefusedError:
        result["error"] = f"Connection refused on port {port}"
    except Exception as e:
        result["error"] = str(e)

    return result


def get_ip_info(ip: Optional[str] = None) -> dict:
    """
    Get geolocation and network info for an IP address.
    Uses the free ip-api.com JSON API (no key required, rate-limited to 45 req/min).
    If no IP is provided, returns info for the caller's public IP.
    """
    endpoint = f"http://ip-api.com/json/{ip or ''}"
    try:
        req = urllib.request.Request(endpoint, headers={"User-Agent": "CyberSecToolkit/1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
        if data.get("status") == "fail":
            return {"error": data.get("message", "Lookup failed"), "query": ip or "public"}
        return data
    except urllib.error.URLError as e:
        return {"error": f"Network request failed: {e}", "query": ip or "public"}
    except Exception as e:
        return {"error": str(e), "query": ip or "public"}


def check_port_publicly_reachable(host: str, port: int, timeout: float = 3.0) -> dict:
    """Check if a specific port on a host is reachable from this machine."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.monotonic() - start) * 1000
            return {
                "host": host,
                "port": port,
                "reachable": True,
                "response_ms": round(elapsed, 1),
            }
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {
            "host": host,
            "port": port,
            "reachable": False,
            "error": str(e),
        }


def whois_like_info(hostname: str) -> dict:
    """
    Combine DNS, IP geolocation, and SSL info for a comprehensive host profile.
    """
    dns = dns_lookup(hostname)
    result = {"hostname": hostname, "dns": dns}

    if dns["forward_records"]:
        primary_ip = dns["forward_records"][0]
        result["ip_info"] = get_ip_info(primary_ip)

    ssl_info = get_ssl_certificate_info(hostname)
    if not ssl_info.get("error"):
        result["ssl"] = ssl_info

    return result
