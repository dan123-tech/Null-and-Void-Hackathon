from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass
from typing import Iterable, List, Optional

from manuf import MacParser


@dataclass(frozen=True)
class DiscoveredHost:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None


_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")


def _run(cmd: list[str], timeout_s: int = 20) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    return (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")


def guess_device_type(vendor: str | None, hostname: str | None) -> str | None:
    v = (vendor or "").lower()
    h = (hostname or "").lower()
    if any(x in v for x in ["apple", "samsung", "xiaomi", "huawei", "oneplus", "google"]):
        return "phone"
    if any(x in v for x in ["dell", "lenovo", "hp", "hewlett", "asus", "acer", "msi", "microsoft"]):
        return "laptop"
    if any(x in v for x in ["raspberry", "espressif", "tuya", "sonoff"]):
        return "iot"
    if any(x in v for x in ["ubiquiti", "mikrotik", "tp-link", "netgear", "cisco"]):
        return "router"
    if any(x in h for x in ["iphone", "android", "ipad"]):
        return "phone"
    if any(x in h for x in ["laptop", "macbook", "thinkpad"]):
        return "laptop"
    return None


def parse_ip_neigh() -> list[DiscoveredHost]:
    """
    Uses the kernel neighbor table (ARP/NDP). Works well on Raspberry Pi host.
    Inside Docker you may see fewer entries unless traffic/scan occurs.
    """
    out = _run(["sh", "-lc", "ip neigh show || true"], timeout_s=10)
    hosts: list[DiscoveredHost] = []
    for line in out.splitlines():
        # Example: 10.136.37.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        mac = None
        if "lladdr" in parts:
            i = parts.index("lladdr")
            if i + 1 < len(parts) and _MAC_RE.search(parts[i + 1]):
                mac = parts[i + 1].lower()
        hosts.append(DiscoveredHost(ip=ip, mac=mac))
    return hosts


def detect_local_subnets() -> list[str]:
    """
    Best-effort: infer LAN /24 from default route source IP.
    """
    out = _run(["sh", "-lc", "ip route get 1.1.1.1 2>/dev/null || true"], timeout_s=5)
    m = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)\b", out)
    if not m:
        return []
    src = ipaddress.ip_address(m.group(1))
    net = ipaddress.ip_network(f"{src}/24", strict=False)
    return [str(net)]


def nmap_ping_sweep(cidr: str) -> list[DiscoveredHost]:
    """
    Requires nmap installed. Returns IP, MAC (sometimes), hostname.
    """
    out = _run(["sh", "-lc", f"nmap -sn {cidr} -oG - 2>/dev/null || true"], timeout_s=40)
    hosts: list[DiscoveredHost] = []
    # Grepable format lines contain: Host: 10.0.0.1 ()  Status: Up
    # Optional MAC: MAC Address: AA:BB... (Vendor)
    current: dict[str, DiscoveredHost] = {}
    for line in out.splitlines():
        if not line.startswith("Host:"):
            continue
        # Host: 10.136.37.1 ()  Status: Up
        m = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)\s+\(([^)]*)\)\s+Status:\s+Up", line)
        if m:
            ip = m.group(1)
            hn = m.group(2) or None
            current[ip] = DiscoveredHost(ip=ip, hostname=hn)
            continue
        # Host: ...  Ports: ...  MAC Address: AA:BB:... (Vendor)
        m2 = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+).+MAC Address:\s+([0-9A-F:]{17})\s+\(([^)]*)\)", line)
        if m2:
            ip = m2.group(1)
            mac = m2.group(2).lower()
            vendor = m2.group(3) or None
            prev = current.get(ip, DiscoveredHost(ip=ip))
            current[ip] = DiscoveredHost(ip=ip, mac=mac, hostname=prev.hostname, vendor=vendor)
    hosts = list(current.values())
    return hosts


def enrich_vendor_and_type(hosts: Iterable[DiscoveredHost]) -> list[DiscoveredHost]:
    parser = MacParser()
    out: list[DiscoveredHost] = []
    for h in hosts:
        vendor = h.vendor
        if not vendor and h.mac:
            try:
                vendor = parser.get_manuf(h.mac) or None
            except Exception:
                vendor = None
        device_type = h.device_type or guess_device_type(vendor, h.hostname)
        out.append(DiscoveredHost(ip=h.ip, mac=h.mac, hostname=h.hostname, vendor=vendor, device_type=device_type))
    return out


def discover_all() -> List[DiscoveredHost]:
    neigh = parse_ip_neigh()
    subnets = detect_local_subnets()
    swept: list[DiscoveredHost] = []
    for s in subnets:
        swept.extend(nmap_ping_sweep(s))
    # Merge by IP (prefer sweep info)
    by_ip: dict[str, DiscoveredHost] = {h.ip: h for h in neigh}
    for h in swept:
        prev = by_ip.get(h.ip)
        if not prev:
            by_ip[h.ip] = h
        else:
            by_ip[h.ip] = DiscoveredHost(
                ip=h.ip,
                mac=h.mac or prev.mac,
                hostname=h.hostname or prev.hostname,
                vendor=h.vendor or prev.vendor,
                device_type=h.device_type or prev.device_type,
            )
    return enrich_vendor_and_type(by_ip.values())

