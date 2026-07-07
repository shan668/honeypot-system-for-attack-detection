"""Network discovery utilities for AegisTrap."""

from __future__ import annotations

import socket
import subprocess
import platform
import re
from typing import Optional


def get_local_ip(fallback: str = "127.0.0.1") -> str:
    """Get the primary local IP address of the host.

    Opens a UDP socket to a public address to determine the local
    outbound interface IP. No packets are actually sent.

    Args:
        fallback: IP address to return if discovery fails.

    Returns:
        Local IP address as a string.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.5)
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return fallback
    finally:
        sock.close()


def resolve_hostname(ip_address: str) -> Optional[str]:
    """Resolve an IP address to a hostname (with a short timeout).

    Args:
        ip_address: IPv4 or IPv6 address.

    Returns:
        Hostname string, or None if resolution fails.
    """
    if not ip_address:
        return None
    try:
        socket.setdefaulttimeout(1.0)
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror, OSError, TimeoutError):
        return None


def get_mac_address(ip_address: str) -> Optional[str]:
    """Retrieve the MAC address for an IP on the local LAN.

    Uses the platform-appropriate ARP table lookup. Returns None
    for remote addresses or when the lookup is not possible.

    Args:
        ip_address: Target IPv4 address.

    Returns:
        MAC address in colon-separated form, or None.
    """
    if not ip_address:
        return None
    if not _is_local_ip(ip_address):
        return None
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output(
                ["arp", "-a", ip_address], stderr=subprocess.DEVNULL, timeout=2
            ).decode("utf-8", errors="ignore")
        else:
            output = subprocess.check_output(
                ["arp", "-n", ip_address], stderr=subprocess.DEVNULL, timeout=2
            ).decode("utf-8", errors="ignore")
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None

    mac_pattern = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
    match = mac_pattern.search(output)
    if match:
        return match.group(0).upper().replace("-", ":")
    return None


def _is_local_ip(ip_address: str) -> bool:
    """Check if an IP is in a private/local range.

    Args:
        ip_address: IP address string.

    Returns:
        True if the address is in a private range.
    """
    try:
        octets = ip_address.split(".")
        if len(octets) != 4:
            return False
        first = int(octets[0])
        second = int(octets[1])
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:
            return True
        return False
    except (ValueError, AttributeError):
        return False

