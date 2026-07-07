"""Session lifecycle management for AegisTrap.

A session represents a single TCP connection from a remote peer to one of
the honeypot services. The :class:`Session` dataclass is the in-memory
record; the :class:`SessionManager` is responsible for starting new
sessions, persisting session-related events (commands, credentials,
files, ...) through the :class:`Database`, and finalising sessions when
the underlying socket closes.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from aegistrap.core.database import Database
from aegistrap.core.logger import StructuredLogger
from aegistrap.utils.geoip import get_geoip_info
from aegistrap.utils.helpers import generate_session_id
from aegistrap.utils.network import get_mac_address, resolve_hostname


@dataclass
class Session:
    """In-memory representation of a single honeypot session."""

    id: str
    protocol: str
    source_ip: str
    source_port: int
    dest_port: int
    started_at: float
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    continent: Optional[str] = None
    user_agent: Optional[str] = None
    ended_at: Optional[float] = None
    duration_ms: Optional[int] = None
    bytes_in: int = 0
    bytes_out: int = 0
    outcome: Optional[str] = None
    severity: str = "informational"
    notes: Optional[str] = None
    commands: list[dict[str, Any]] = field(default_factory=list)
    credentials: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_db_row(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_port": self.dest_port,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "isp": self.isp,
            "continent": self.continent,
            "user_agent": self.user_agent,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "outcome": self.outcome,
            "severity": self.severity,
            "notes": self.notes,
        }

    def close(self, outcome: str = "closed", severity: Optional[str] = None,
              notes: Optional[str] = None) -> None:
        now = time.time()
        self.ended_at = now
        self.outcome = outcome
        if severity is not None:
            self.severity = severity
        if notes is not None:
            self.notes = notes
        try:
            self.duration_ms = int(max(0.0, (now - self.started_at)) * 1000)
        except Exception:  # pragma: no cover
            self.duration_ms = 0


class SessionManager:
    """Thread-safe orchestrator of session lifecycle events."""

    def __init__(
        self,
        database: Database,
        logger: StructuredLogger,
        on_session_closed: Optional[Callable[[Session], None]] = None,
    ) -> None:
        self.db = database
        self.logger = logger
        self.on_session_closed = on_session_closed
        self._lock = threading.RLock()
        self._active: dict[str, Session] = {}
        self._counters: dict[str, int] = {}

    def start_session(
        self,
        protocol: str,
        source_ip: str,
        source_port: int,
        dest_port: int,
        user_agent: Optional[str] = None,
        resolve_geo: bool = True,
    ) -> Session:
        session_id = generate_session_id()
        started_at = time.time()
        session = Session(
            id=session_id,
            protocol=protocol,
            source_ip=source_ip,
            source_port=int(source_port) if source_port else 0,
            dest_port=int(dest_port) if dest_port else 0,
            started_at=started_at,
        )

        if resolve_geo:
            try:
                session.hostname = resolve_hostname(source_ip)
            except Exception:  # pragma: no cover
                session.hostname = None
            try:
                session.mac_address = get_mac_address(source_ip)
            except Exception:  # pragma: no cover
                session.mac_address = None
            try:
                geo = get_geoip_info(source_ip) or {}
                session.country = geo.get("country")
                session.country_code = geo.get("country_code")
                session.city = geo.get("city")
                session.isp = geo.get("isp")
                session.continent = geo.get("continent")
            except Exception:  # pragma: no cover
                pass

        if user_agent:
            session.user_agent = user_agent

        with self._lock:
            self._active[session_id] = session
            self._counters[protocol] = self._counters.get(protocol, 0) + 1
            attempt_number = self._counters[protocol]

        try:
            self.db.insert_session(session.to_db_row())
        except Exception as exc:  # pragma: no cover
            self.logger.error(
                "Failed to persist new session",
                error=str(exc),
                session_id=session_id,
            )

        self.logger.info(
            "Session started",
            session_id=session_id,
            protocol=protocol,
            source_ip=source_ip,
            source_port=source_port,
            dest_port=dest_port,
        )
        session.metadata["attempt_number"] = attempt_number
        session.metadata["last_update"] = started_at
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self._active.get(session_id)

    def list_active_sessions(self) -> list[Session]:
        with self._lock:
            return list(self._active.values())

    def close_session(
        self,
        session_id: str,
        outcome: str = "closed",
        severity: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Optional[Session]:
        with self._lock:
            session = self._active.pop(session_id, None)
        if session is None:
            return None
        session.close(outcome=outcome, severity=severity, notes=notes)
        try:
            self.db.update_session(session_id, session.to_db_row())
        except Exception as exc:  # pragma: no cover
            self.logger.error(
                "Failed to persist session close",
                error=str(exc),
                session_id=session_id,
            )
        self.logger.info(
            "Session closed",
            session_id=session_id,
            protocol=session.protocol,
            source_ip=session.source_ip,
            outcome=outcome,
            severity=session.severity,
            duration_ms=session.duration_ms,
            bytes_in=session.bytes_in,
            bytes_out=session.bytes_out,
        )
        if self.on_session_closed is not None:
            try:
                self.on_session_closed(session)
            except Exception as exc:  # pragma: no cover
                self.logger.error(
                    "on_session_closed callback failed",
                    error=str(exc),
                    session_id=session_id,
                )
        return session

    def set_severity(self, session_id: str, severity: str, notes: Optional[str] = None) -> None:
        with self._lock:
            session = self._active.get(session_id)
            if session is None:
                self.db.update_session(session_id, {"severity": severity, "notes": notes})
                return
            session.severity = severity
            if notes is not None:
                session.notes = notes
        self.db.update_session(session_id, {"severity": severity, "notes": notes})

    def cleanup_stale(self, timeout_seconds: int = 600) -> int:
        """Close active sessions that have been idle for too long."""
        now = time.time()
        stale_ids: list[str] = []
        with self._lock:
            for session_id, session in self._active.items():
                last_update = float(session.metadata.get("last_update", session.started_at))
                if now - last_update >= timeout_seconds:
                    stale_ids.append(session_id)

        for session_id in stale_ids:
            self.close_session(
                session_id,
                outcome="timeout",
                severity="informational",
                notes="Session closed by stale-session cleanup",
            )
        return len(stale_ids)
