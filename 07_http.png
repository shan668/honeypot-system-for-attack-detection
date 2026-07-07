"""Human-friendly interpretation of captured honeypot probes."""

from __future__ import annotations

import string
from typing import Any


PRINTABLE = set(string.printable)


def analyze_command(row: dict[str, Any]) -> dict[str, Any]:
    protocol = str(row.get("protocol") or "").lower()
    command = str(row.get("command") or "")
    upper = command.strip().upper()

    if looks_binary(command):
        return _analysis(
            "Binary service-detection probe",
            "Likely Nmap or another scanner fingerprinting this port. This is not a real FTP/SSH command.",
            "scanner_probe",
            "low",
            command,
        )
    if "NMAP" in upper:
        return _analysis(
            "Nmap protocol probe",
            "Nmap is trying to identify the service and version exposed on this port.",
            "scanner_probe",
            "low",
            command,
        )

    if protocol == "ftp":
        verb = upper.split(" ", 1)[0] if upper else ""
        mapping = {
            "USER": ("FTP username attempt", "The device is trying an FTP login username.", "login_attempt", "medium"),
            "PASS": ("FTP password attempt", "The device is trying an FTP password.", "login_attempt", "medium"),
            "SYST": ("FTP capability enumeration", "The device is asking what FTP server type is available.", "enumeration", "low"),
            "FEAT": ("FTP capability enumeration", "The device is asking what FTP features are available.", "enumeration", "low"),
            "HELP": ("FTP capability enumeration", "The device is asking for FTP help/features.", "enumeration", "low"),
            "PWD": ("FTP directory navigation", "The device is checking the current FTP directory.", "enumeration", "low"),
            "XPWD": ("FTP directory navigation", "The device is checking the current FTP directory.", "enumeration", "low"),
            "CWD": ("FTP directory navigation", "The device is trying to change FTP directories.", "enumeration", "medium"),
            "LIST": ("FTP directory listing", "The device is trying to list files on the fake FTP server.", "enumeration", "medium"),
            "NLST": ("FTP directory listing", "The device is trying to list file names on the fake FTP server.", "enumeration", "medium"),
            "RETR": ("FTP file download attempt", "The device is trying to download a file.", "file_access", "high"),
            "STOR": ("FTP file upload attempt", "The device is trying to upload a file.", "file_access", "high"),
            "DELE": ("FTP file delete attempt", "The device is trying to delete a file.", "file_access", "high"),
        }
        if verb in mapping:
            intent, meaning, category, risk = mapping[verb]
            return _analysis(intent, meaning, category, risk, command)
        if verb in {"GET", "POST", "HEAD", "OPTIONS"}:
            return _analysis(
                "HTTP probe sent to FTP port",
                "A scanner tried HTTP-style traffic against the FTP honeypot.",
                "cross_protocol_probe",
                "low",
                command,
            )
        return _analysis(
            "Unknown FTP command/probe",
            "The payload reached the FTP honeypot but is not a normal FTP command.",
            "ftp_unknown",
            "low",
            command,
        )

    if protocol == "ssh":
        if upper in {"WHOAMI", "ID", "UNAME -A", "PWD", "LS"}:
            return _analysis(
                "Shell reconnaissance command",
                "The device is checking identity, OS, location, or files after reaching the fake shell.",
                "post_login_command",
                "high",
                command,
            )
        return _analysis(
            "Shell command attempt",
            "The device typed a command into the fake SSH shell.",
            "post_login_command",
            "medium",
            command,
        )

    return _analysis(
        "Unknown activity",
        "The remote device sent data, but it does not match a known command pattern.",
        "unknown",
        "low",
        command,
    )


def analyze_credential(row: dict[str, Any]) -> dict[str, Any]:
    protocol = str(row.get("protocol") or "").lower()
    username = str(row.get("username") or "")
    password = str(row.get("password") or "")

    if "NMAP" in username.upper() or username.startswith("SSH-"):
        return {
            "intent": "SSH scanner handshake",
            "meaning": "This is Nmap identifying the SSH service, not a real username/password login.",
            "category": "scanner_probe",
            "risk": "low",
            "display_username": readable_preview(username),
            "display_password": readable_preview(password),
        }

    if protocol == "ftp" and username.lower() == "anonymous":
        return {
            "intent": "FTP anonymous login attempt",
            "meaning": "The device is trying anonymous FTP access.",
            "category": "login_attempt",
            "risk": "medium",
            "display_username": username,
            "display_password": readable_preview(password),
        }

    if protocol == "http":
        return {
            "intent": "HTTP web login attempt",
            "meaning": "The device submitted credentials to a fake web login page.",
            "category": "login_attempt",
            "risk": "medium",
            "display_username": readable_preview(username),
            "display_password": readable_preview(password),
        }

    return {
        "intent": "Credential login attempt",
        "meaning": f"The device tried to log in to {protocol.upper()} with these credentials.",
        "category": "login_attempt",
        "risk": "medium",
        "display_username": readable_preview(username),
        "display_password": readable_preview(password),
    }


def decode_network_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", "replace")


def _analysis(intent: str, meaning: str, category: str, risk: str, value: str) -> dict[str, Any]:
    return {
        "intent": intent,
        "meaning": meaning,
        "category": category,
        "risk": risk,
        "display_command": readable_preview(value),
        "raw_preview": raw_preview(value),
    }


def readable_preview(value: str, limit: int = 140) -> str:
    if not value:
        return ""
    if looks_binary(value):
        return f"[binary probe] {raw_preview(value, limit=48)}"
    cleaned = "".join(ch if ch in PRINTABLE and ch not in "\r\n\t" else "." for ch in value)
    return cleaned[:limit] + ("..." if len(cleaned) > limit else "")


def raw_preview(value: str, limit: int = 64) -> str:
    if not value:
        return ""
    data = value.encode("latin-1", "replace")
    return " ".join(f"{byte:02x}" for byte in data[:limit])


def looks_binary(value: str) -> bool:
    if not value:
        return False
    if "\ufffd" in value:
        return True
    control_count = sum(1 for ch in value if ord(ch) < 32 and ch not in "\r\n\t")
    printable_count = sum(1 for ch in value if ch in PRINTABLE)
    if control_count >= 2:
        return True
    return printable_count / max(1, len(value)) < 0.65
