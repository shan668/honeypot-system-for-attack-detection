"""IP geolocation utilities for AegisTrap.

The AegisTrap threat intelligence platform provides a lightweight
offline geolocation capability based on the well-known IANA allocations
for private and loopback ranges. This is used for dashboard purposes
when no external IP geolocation service is reachable. It is intentionally
self-contained so the platform remains functional in air-gapped
environments.
"""

from __future__ import annotations

from typing import Optional

# Country code -> (continent, friendly name) map for the most common
# regional blocks used on a typical LAN. This is intentionally
# approximate; for production deployments a MaxMind GeoLite2 database
# can be plugged into ``lookup()`` below.
_PRIVATE_COUNTRY_MAP: dict[str, tuple[str, str]] = {
    "127.0.0.0": ("Loopback", "Localhost"),
    "10.0.0.0": ("Private", "RFC1918 10.0.0.0/8"),
    "172.16.0.0": ("Private", "RFC1918 172.16.0.0/12"),
    "192.168.0.0": ("Private", "RFC1918 192.168.0.0/16"),
}


def get_geoip_info(ip_address: str) -> dict[str, Optional[str]]:
    """Return geolocation information for an IP address.

    The function first checks the offline private-range map. It then
    falls back to a simple ``ip-api.com`` JSON endpoint (network
    permitting) to enrich the result. Both steps are best-effort;
    failures are silently tolerated because the dashboard is fully
    functional with the local approximation alone.

    Args:
        ip_address: IPv4 or IPv6 address.

    Returns:
        A dictionary with keys ``country``, ``country_code``, ``city``,
        ``region``, ``isp``, ``continent`` and ``source``.
    """
    info: dict[str, Optional[str]] = {
        "country": None,
        "country_code": None,
        "city": None,
        "region": None,
        "isp": None,
        "continent": None,
        "source": "none",
    }
    if not ip_address:
        return info

    # Step 1: local heuristic
    for prefix, (continent, country) in _PRIVATE_COUNTRY_MAP.items():
        if ip_address == prefix or ip_address.startswith(prefix.rstrip(".0")):
            info["country"] = country
            info["continent"] = continent
            info["source"] = "local"
            return info

    # Step 2: optional online lookup
    try:
        import json
        import urllib.request
        import urllib.parse

        url = f"http://ip-api.com/json/{urllib.parse.quote(ip_address)}?fields=status,country,countryCode,regionName,city,isp,continent"
        req = urllib.request.Request(url, headers={"User-Agent": "AegisTrap/1.0"})
        with urllib.request.urlopen(req, timeout=2) as response:  # nosec - defensive lookup only
            payload = json.loads(response.read().decode("utf-8", errors="ignore"))
        if payload.get("status") == "success":
            info.update({
                "country": payload.get("country"),
                "country_code": payload.get("countryCode"),
                "city": payload.get("city"),
                "region": payload.get("regionName"),
                "isp": payload.get("isp"),
                "continent": payload.get("continent"),
                "source": "ip-api",
            })
    except Exception:
        # Best-effort: keep the local heuristic when offline.
        pass

    return info

