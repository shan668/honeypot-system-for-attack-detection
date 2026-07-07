"""General helper utilities for AegisTrap."""

from __future__ import annotations

import hashlib
import random
import re
import string
import time
import uuid
from typing import Any, Optional


def generate_session_id() -> str:
    """Generate a unique session identifier.

    Returns:
        A 32-character hexadecimal session ID.
    """
    return uuid.uuid4().hex


def safe_str(data: bytes, encoding: str = "utf-8", errors: str = "replace") -> str:
    """Safely decode bytes to string.

    Args:
        data: Raw bytes to decode.
        encoding: Target encoding (default UTF-8).
        errors: Error handling strategy.

    Returns:
        Decoded string.
    """
    if isinstance(data, str):
        return data
    if data is None:
        return ""
    try:
        return data.decode(encoding, errors=errors)
    except (UnicodeDecodeError, AttributeError):
        return str(data)


def truncate(value: Any, max_length: int = 200) -> str:
    """Truncate a value to a maximum length with ellipsis.

    Args:
        value: The value to truncate.
        max_length: Maximum length of the returned string.

    Returns:
        Truncated string representation.
    """
    text = str(value) if value is not None else ""
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def format_bytes(num_bytes: int) -> str:
    """Format a byte count as a human-readable string.

    Args:
        num_bytes: Number of bytes.

    Returns:
        Human-readable byte size (e.g. '1.5 MB').
    """
    if num_bytes is None:
        return "0 B"
    try:
        num_bytes = int(num_bytes)
    except (TypeError, ValueError):
        return "0 B"
    if num_bytes < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    for unit in units:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def format_duration(seconds: float) -> str:
    """Format a duration in seconds as a human-readable string.

    Args:
        seconds: Duration in seconds.

    Returns:
        Formatted duration (e.g. '2m 34s').
    """
    if seconds is None or seconds < 0:
        return "0s"
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "0s"
    if seconds < 1:
        return f"{int(seconds * 1000)}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, mins = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {mins}m"
    days, hrs = divmod(hours, 24)
    return f"{days}d {hrs}h"


def parse_http_headers(raw_headers: str) -> dict[str, str]:
    """Parse raw HTTP header text into a dictionary.

    Args:
        raw_headers: Multi-line raw HTTP header text.

    Returns:
        Dictionary of header name to value.
    """
    headers: dict[str, str] = {}
    if not raw_headers:
        return headers
    for line in raw_headers.splitlines():
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    return headers


_SUSPICIOUS_PATTERNS = [
    (re.compile(r"(?i)(?:union|select|insert|update|delete|drop)\s"), "sql_keywords"),
    (re.compile(r"(?i)<\s*script\b"), "xss_script"),
    (re.compile(r"(?i)(?:\.\./|\.\.\|%2e%2e)"), "path_traversal"),
    (re.compile(r"(?i)(?:%00|\x00)"), "null_byte"),
    (re.compile(r"(?i)(?:/etc/passwd|/etc/shadow)"), "linux_file_probe"),
    (re.compile(r"(?i)(?:\b(?:cmd|exec|system|eval)\s*\()"), "command_injection"),
    (re.compile(r"(?i)\bnmap\b|\bmasscan\b|\bnikto\b|\bsqlmap\b|\bdirbuster\b|\bgobuster\b"), "scanner_signature"),
]


def detect_suspicious_patterns(text: str) -> list[str]:
    """Detect suspicious patterns in a piece of text.

    Args:
        text: Text to inspect.

    Returns:
        List of pattern labels that matched.
    """
    if not text:
        return []
    matches: list[str] = []
    for pattern, label in _SUSPICIOUS_PATTERNS:
        if pattern.search(text):
            matches.append(label)
    return matches


def random_delay(min_ms: int = 50, max_ms: int = 400) -> float:
    """Return a random delay in seconds for realistic timing.

    Args:
        min_ms: Minimum delay in milliseconds.
        max_ms: Maximum delay in milliseconds.

    Returns:
        Delay in seconds.
    """
    return random.uniform(min_ms / 1000.0, max_ms / 1000.0)


def constant_time_compare(val1: str, val2: str) -> bool:
    """Constant-time string comparison to deter timing attacks.

    Args:
        val1: First string.
        val2: Second string.

    Returns:
        True if the strings are equal.
    """
    return hashlib.sha256(val1.encode()).digest() == hashlib.sha256(val2.encode()).digest()


def random_string(length: int = 8, alphabet: Optional[str] = None) -> str:
    """Generate a random string of fixed length.

    Args:
        length: Desired string length.
        alphabet: Optional character set.

    Returns:
        Random string.
    """
    if alphabet is None:
        alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def epoch_to_iso(timestamp: float | None = None) -> str:
    """Convert an epoch timestamp to an ISO 8601 string.

    Args:
        timestamp: Epoch seconds (defaults to current time).

    Returns:
        ISO 8601 formatted string.
    """
    from datetime import datetime, timezone
    if timestamp is None:
        timestamp = time.time()
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()

