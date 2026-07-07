"""Threat intelligence engine for AegisTrap.

The threat engine analyses session events to identify hostile
behaviour. It operates on a sliding window of activity per source IP,
per username, and per URL, and produces :class:`ThreatEvent` records
that the database persists in the ``alerts`` table.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Optional

from aegistrap.core.config import ThreatConfig
from aegistrap.core.database import Database
from aegistrap.core.logger import StructuredLogger
from aegistrap.core.session import Session


SEVERITY_LEVELS = ("informational", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITY_LEVELS)}


@dataclass
class ThreatEvent:
    """A single threat detection result."""

    threat_type: str
    severity: str
    source_ip: Optional[str]
    description: str
    details: dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class _IPWindow:
    """Sliding window of activity for a single source IP."""

    def __init__(self, window_seconds: int) -> None:
        self.window_seconds = max(1, int(window_seconds))
        self.window_started: float = time.time()
        self.events: Deque[tuple[float, dict[str, Any]]] = deque()
        self.failed_logins: int = 0
        self.successful_logins: int = 0
        self.credentials: list[tuple[str, str, float]] = []
        self.usernames: set[str] = set()
        self.unique_paths: set[str] = set()
        self.unique_user_agents: set[str] = set()
        self.commands: Deque[tuple[float, str]] = deque()
        self.requests: Deque[float] = deque()
        self.banner_grabs: int = 0
        self.port_scan_hits: int = 0
        self.suspicious_pattern_hits: int = 0
        self.lock = threading.Lock()

    def evict(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()
        while self.requests and self.requests[0] < cutoff:
            self.requests.popleft()
        while self.commands and self.commands[0][0] < cutoff:
            self.commands.popleft()
        self.credentials = [c for c in self.credentials if c[2] >= cutoff]


class ThreatEngine:
    """Real-time threat detection engine."""

    def __init__(
        self,
        config: ThreatConfig,
        database: Database,
        logger: StructuredLogger,
        on_alert: Optional[Callable[[ThreatEvent], None]] = None,
    ) -> None:
        self.config = config
        self.db = database
        self.logger = logger
        self._on_alert = on_alert
        self._lock = threading.Lock()
        self._windows: dict[str, _IPWindow] = {}
        self._global_alerts: dict[tuple, float] = {}
        self._last_cleanup = time.time()

    def record_login_attempt(
        self,
        source_ip: str,
        protocol: str,
        username: str,
        success: bool,
        session_id: Optional[str] = None,
    ) -> list[ThreatEvent]:
        window = self._window_for(source_ip)
        with window.lock:
            window.evict(time.time())
            window.credentials.append((username or "", "", time.time()))
            window.usernames.add(username or "")
            if success:
                window.successful_logins += 1
            else:
                window.failed_logins += 1
        return self._evaluate(
            source_ip, session_id=session_id, protocol=protocol
        )

    def record_command(
        self,
        source_ip: str,
        protocol: str,
        command: str,
        session_id: Optional[str] = None,
    ) -> list[ThreatEvent]:
        window = self._window_for(source_ip)
        with window.lock:
            window.evict(time.time())
            window.commands.append((time.time(), command))
        return self._evaluate(
            source_ip, session_id=session_id, protocol=protocol
        )

    def record_request(
        self,
        source_ip: str,
        method: str,
        path: str,
        user_agent: Optional[str] = None,
        status_code: Optional[int] = None,
        session_id: Optional[str] = None,
    ) -> list[ThreatEvent]:
        window = self._window_for(source_ip)
        with window.lock:
            window.evict(time.time())
            window.requests.append(time.time())
            if path:
                window.unique_paths.add(path)
            if user_agent:
                window.unique_user_agents.add(user_agent)
        return self._evaluate(
            source_ip,
            session_id=session_id,
            method=method,
            path=path,
            status_code=status_code,
        )

    def record_banner_grab(
        self,
        source_ip: str,
        session_id: Optional[str] = None,
    ) -> list[ThreatEvent]:
        window = self._window_for(source_ip)
        with window.lock:
            window.banner_grabs += 1
            window.port_scan_hits += 1
        return self._evaluate(source_ip, session_id=session_id, banner_grab=True)

    def record_port_probe(
        self,
        source_ip: str,
        session_id: Optional[str] = None,
    ) -> list[ThreatEvent]:
        window = self._window_for(source_ip)
        with window.lock:
            window.port_scan_hits += 1
        return self._evaluate(source_ip, session_id=session_id, port_scan=True)

    def record_suspicious_pattern(
        self,
        source_ip: str,
        pattern_label: str,
        session_id: Optional[str] = None,
    ) -> list[ThreatEvent]:
        window = self._window_for(source_ip)
        with window.lock:
            window.suspicious_pattern_hits += 1
        return self._evaluate(
            source_ip, session_id=session_id, pattern_label=pattern_label
        )

    def evaluate_session(self, session: Session) -> list[ThreatEvent]:
        return self._evaluate(
            session.source_ip,
            session_id=session.id,
            protocol=session.protocol,
        )

    def periodic_cleanup(self) -> None:
        """Drop stale IP windows to bound memory usage."""
        now = time.time()
        with self._lock:
            stale = [
                ip for ip, w in self._windows.items()
                if now - max((e[0] for e in w.events), default=w.window_started) > self.config.window_seconds * 4
            ]
            for ip in stale:
                self._windows.pop(ip, None)
        self._global_alerts = {
            key: ts for key, ts in self._global_alerts.items()
            if now - ts < self.config.window_seconds * 4
        }
        self._last_cleanup = now

    def _window_for(self, source_ip: str) -> _IPWindow:
        with self._lock:
            window = self._windows.get(source_ip)
            if window is None:
                window = _IPWindow(self.config.window_seconds)
                window.window_started = time.time()
                self._windows[source_ip] = window
            return window

    def _evaluate(
        self,
        source_ip: str,
        session_id: Optional[str] = None,
        protocol: Optional[str] = None,
        method: Optional[str] = None,
        path: Optional[str] = None,
        status_code: Optional[int] = None,
        banner_grab: bool = False,
        port_scan: bool = False,
        pattern_label: Optional[str] = None,
    ) -> list[ThreatEvent]:
        """Inspect the sliding window for ``source_ip`` and emit alerts."""
        if not source_ip:
            return []
        window = self._window_for(source_ip)
        events: list[ThreatEvent] = []
        with window.lock:
            window.evict(time.time())
            req_count = len(window.requests)
            cmd_count = len(window.commands)
            failed = window.failed_logins
            successful = window.successful_logins
            paths = len(window.unique_paths)
            users = len(window.usernames)
            uas = len(window.unique_user_agents)

        if failed >= self.config.failed_login_threshold:
            severity = "medium" if failed < self.config.failed_login_threshold * 3 else "high"
            if any(u in window.usernames for u in ("root", "admin", "administrator")):
                severity = "high"
            evt = self._emit(("brute_force", source_ip), "brute_force", severity, source_ip,
                             f"{failed} failed login attempts from {source_ip}",
                             {"failed_logins": failed, "successful_logins": successful,
                              "usernames": sorted(window.usernames)[:25], "protocol": protocol},
                             session_id)
            if evt is not None:
                events.append(evt)
        if len(window.credentials) >= self.config.credential_stuffing_threshold:
            evt = self._emit(("credential_stuffing", source_ip), "credential_stuffing", "high", source_ip,
                             f"{len(window.credentials)} distinct credential pairs from {source_ip}",
                             {"attempts": len(window.credentials)}, session_id)
            if evt is not None:
                events.append(evt)
        if users >= self.config.unique_user_threshold:
            evt = self._emit(("password_spraying", source_ip), "password_spraying", "medium", source_ip,
                             f"{users} unique usernames probed from {source_ip}",
                             {"usernames": sorted(window.usernames)[:50]}, session_id)
            if evt is not None:
                events.append(evt)
        if req_count >= self.config.request_rate_threshold:
            evt = self._emit(("high_request_rate", source_ip), "high_request_rate", "medium", source_ip,
                             f"{req_count} HTTP requests in {self.config.window_seconds}s from {source_ip}",
                             {"request_count": req_count, "user_agents": uas}, session_id)
            if evt is not None:
                events.append(evt)
        if paths >= self.config.directory_bruteforce_threshold:
            evt = self._emit(("directory_bruteforce", source_ip), "directory_bruteforce", "high", source_ip,
                             f"{paths} unique paths probed from {source_ip}",
                             {"unique_paths": paths}, session_id)
            if evt is not None:
                events.append(evt)
        if cmd_count >= self.config.ssh_command_threshold and protocol == "ssh":
            evt = self._emit(("ssh_command_burst", source_ip), "ssh_command_burst", "medium", source_ip,
                             f"{cmd_count} SSH commands in {self.config.window_seconds}s",
                             {"commands": cmd_count}, session_id)
            if evt is not None:
                events.append(evt)
        if cmd_count >= self.config.ftp_command_threshold and protocol == "ftp":
            evt = self._emit(("ftp_command_burst", source_ip), "ftp_command_burst", "low", source_ip,
                             f"{cmd_count} FTP commands in {self.config.window_seconds}s",
                             {"commands": cmd_count}, session_id)
            if evt is not None:
                events.append(evt)
        if banner_grab and window.banner_grabs >= 2:
            evt = self._emit(("banner_grab", source_ip), "banner_grab", "low", source_ip,
                             f"Banner-grab activity from {source_ip}",
                             {"banner_grabs": window.banner_grabs}, session_id)
            if evt is not None:
                events.append(evt)
        if port_scan and window.port_scan_hits >= 3:
            evt = self._emit(("port_scan", source_ip), "port_scan", "medium", source_ip,
                             f"Port scan pattern from {source_ip}",
                             {"port_scan_hits": window.port_scan_hits}, session_id)
            if evt is not None:
                events.append(evt)
        if pattern_label and window.suspicious_pattern_hits >= 1:
            evt = self._emit(("suspicious_pattern", source_ip, pattern_label), "suspicious_pattern", "medium", source_ip,
                             f"Suspicious pattern {pattern_label!r} from {source_ip}",
                             {"pattern": pattern_label, "hits": window.suspicious_pattern_hits}, session_id)
            if evt is not None:
                events.append(evt)
        score = failed * 5 + req_count // 5 + paths * 3 + users * 2 + cmd_count + window.port_scan_hits * 2 + window.suspicious_pattern_hits * 4
        if score >= self.config.auto_block_threshold:
            evt = self._emit(("auto_block", source_ip), "auto_block_candidate", "critical", source_ip,
                             f"Score {score} from {source_ip} exceeds auto-block threshold",
                             {"score": score}, session_id)
            if evt is not None:
                events.append(evt)
        return events

    def _emit(self, key, threat_type, severity, source_ip, description, details, session_id):
        now = time.time()
        with self._lock:
            last = self._global_alerts.get(key)
            if last is not None and now - last < self.config.window_seconds:
                return None
            self._global_alerts[key] = now
        event = ThreatEvent(threat_type=threat_type, severity=severity, source_ip=source_ip,
                            description=description, details=details, session_id=session_id, timestamp=now)
        try:
            self.db.insert_alert(event)
        except Exception as exc:
            self.logger.error("Failed to persist alert", error=str(exc))
        if self._on_alert is not None:
            try:
                self._on_alert(event)
            except Exception as exc:
                self.logger.error("on_alert callback failed", error=str(exc))
        return event
