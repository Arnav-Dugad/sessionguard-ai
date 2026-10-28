"""Offline network-context resolution.

There is no GeoIP database and no internet lookup. Documentation address ranges
(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are mapped to *fictional*
regions so the lab can present realistic-looking context changes without touching
real addresses. Map coordinates are for the stylised dashboard map only.
"""
from __future__ import annotations

import ipaddress
from typing import Any

# (network, region, network name, network type, map x, map y)
_KNOWN: list[tuple[str, str, str, str, float, float]] = [
    ("127.0.0.0/8", "Localhost", "Loopback", "loopback", 0.50, 0.50),
    ("::1/128", "Localhost", "Loopback", "loopback", 0.50, 0.50),
    ("10.0.0.0/8", "Private LAN", "Private network", "private", 0.50, 0.50),
    ("172.16.0.0/12", "Private LAN", "Private network", "private", 0.50, 0.50),
    ("192.168.0.0/16", "Private LAN", "Private network", "private", 0.50, 0.50),
    ("192.0.2.0/25", "Northbridge", "Northbridge Home Fibre (fictional)", "residential", 0.27, 0.36),
    ("192.0.2.128/25", "Northbridge", "Harbour Café Wi-Fi (fictional)", "public-wifi", 0.29, 0.40),
    ("198.51.100.0/24", "Northbridge", "Northbridge Mobile (fictional)", "mobile", 0.25, 0.38),
    ("203.0.113.0/25", "Far Harbor", "Far Harbor Cloud VPS (fictional)", "hosting", 0.78, 0.62),
    ("203.0.113.128/25", "Eastmere", "Eastmere Residential Proxy (fictional)", "proxy", 0.62, 0.28),
]
_NETS = [(ipaddress.ip_network(n), r, name, kind, x, y) for n, r, name, kind, x, y in _KNOWN]


def resolve_network(ip: str | None) -> dict[str, Any]:
    raw = (ip or "").strip() or "0.0.0.0"
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return {"ip": raw, "subnet": "invalid", "region": "Unknown", "network": "Unparseable", "type": "unknown", "x": 0.5, "y": 0.5}

    for net, region, name, kind, x, y in _NETS:
        if addr.version == net.version and addr in net:
            return {"ip": raw, "subnet": str(net), "region": region, "network": name, "type": kind, "x": x, "y": y}

    prefix = 24 if addr.version == 4 else 48
    subnet = str(ipaddress.ip_network(f"{raw}/{prefix}", strict=False))
    return {"ip": raw, "subnet": subnet, "region": "Unknown", "network": "Unclassified network", "type": "unknown", "x": 0.5, "y": 0.5}


def mask_ip(ip: str) -> str:
    """Display helper: keep the network part, hide the host part."""
    if "." in ip:
        parts = ip.split(".")
        return ".".join(parts[:3] + ["x"]) if len(parts) == 4 else ip
    return ip
