"""Analytics engine for AegisTrap.

Provides aggregated views of session, credential, command and alert
data. Results are returned as plain Python dictionaries that are
straightforward to serialise for the dashboard.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from aegistrap.core.database import Database


class AnalyticsEngine:
    """Read-side helpers for the dashboard and reporting."""

    def __init__(self, database: Database) -> None:
        self.db = database

    # ------------------------------------------------------------------ #
    # High-level KPIs
    # ------------------------------------------------------------------ #
    def summary(self) -> dict[str, Any]:
        total_sessions = self._count("SELECT COUNT(*) AS c FROM sessions")
        active_sessions = self._count(
            "SELECT COUNT(*) AS c FROM sessions WHERE ended_at IS NULL"
        )
        total_alerts = self._count("SELECT COUNT(*) AS c FROM alerts")
        total_credentials = self._count("SELECT COUNT(*) AS c FROM credentials")
        total_commands = self._count("SELECT COUNT(*) AS c FROM commands")
        total_files = self._count("SELECT COUNT(*) AS c FROM files")
        total_http = self._count("SELECT COUNT(*) AS c FROM http_requests")
        last_session = self.db.fetchone(
            "SELECT started_at FROM sessions ORDER BY started_at DESC LIMIT 1"
        )
        return {
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "total_alerts": total_alerts,
            "total_credentials": total_credentials,
            "total_commands": total_commands,
            "total_files": total_files,
            "total_http_requests": total_http,
            "last_session_at": (last_session["started_at"] if last_session else None),
        }

    def services(self) -> list[dict[str, Any]]:
        return self.db.list_services()

    def top_attackers(self, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.db.fetchall(
            """
            SELECT source_ip,
                   COUNT(*) AS session_count,
                   MAX(severity) AS max_severity,
                   SUM(bytes_in) AS bytes_in,
                   SUM(bytes_out) AS bytes_out,
                   MAX(country) AS country,
                   MAX(country_code) AS country_code,
                   MAX(city) AS city,
                   MAX(isp) AS isp
            FROM sessions
            GROUP BY source_ip
            ORDER BY session_count DESC
            LIMIT ?
            """,
            (limit,),
        )
        return rows

    def protocol_distribution(self) -> list[dict[str, Any]]:
        return self.db.fetchall(
            """
            SELECT protocol, COUNT(*) AS count
            FROM sessions
            GROUP BY protocol
            ORDER BY count DESC
            """
        )

    def severity_distribution(self) -> list[dict[str, Any]]:
        return self.db.fetchall(
            """
            SELECT severity, COUNT(*) AS count
            FROM alerts
            GROUP BY severity
            ORDER BY count DESC
            """
        )

    def top_usernames(self, limit: int = 10) -> list[dict[str, Any]]:
        return self.db.fetchall(
            """
            SELECT username, COUNT(*) AS count
            FROM credentials
            WHERE username IS NOT NULL AND username <> ''
            GROUP BY username
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit,),
        )

    def top_passwords(self, limit: int = 10) -> list[dict[str, Any]]:
        return self.db.fetchall(
            """
            SELECT password, COUNT(*) AS count
            FROM credentials
            WHERE password IS NOT NULL AND password <> ''
            GROUP BY password
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit,),
        )

    def top_threats(self, limit: int = 10) -> list[dict[str, Any]]:
        return self.db.fetchall(
            """
            SELECT threat_type, severity, COUNT(*) AS count
            FROM alerts
            GROUP BY threat_type, severity
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit,),
        )

    def top_urls(self, limit: int = 20) -> list[dict[str, Any]]:
        return self.db.fetchall(
            """
            SELECT path, method, COUNT(*) AS count
            FROM http_requests
            WHERE path IS NOT NULL
            GROUP BY path, method
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit,),
        )

    def top_commands(self, limit: int = 20) -> list[dict[str, Any]]:
        return self.db.fetchall(
            """
            SELECT command, COUNT(*) AS count, protocol
            FROM commands
            WHERE command IS NOT NULL
            GROUP BY command, protocol
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit,),
        )

    def top_ftp_commands(self, limit: int = 20) -> list[dict[str, Any]]:
        return self.db.fetchall(
            """
            SELECT command, COUNT(*) AS count
            FROM ftp_events
            WHERE command IS NOT NULL
            GROUP BY command
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit,),
        )

    def most_targeted_services(self) -> list[dict[str, Any]]:
        return self.db.fetchall(
            """
            SELECT dest_port, protocol, COUNT(*) AS count
            FROM sessions
            GROUP BY dest_port, protocol
            ORDER BY count DESC
            LIMIT 10
            """
        )

    def attack_timeline(self, hours: int = 24) -> list[dict[str, Any]]:
        cutoff = time.time() - hours * 3600
        return self.db.fetchall(
            """
            SELECT
              CAST((timestamp / 300) AS INTEGER) * 300 AS bucket,
              COUNT(*) AS count
            FROM alerts
            WHERE timestamp >= ?
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            (cutoff,),
        )

    def session_timeline(self, hours: int = 24) -> list[dict[str, Any]]:
        cutoff = time.time() - hours * 3600
        return self.db.fetchall(
            """
            SELECT
              CAST((started_at / 300) AS INTEGER) * 300 AS bucket,
              COUNT(*) AS count,
              protocol
            FROM sessions
            WHERE started_at >= ?
            GROUP BY bucket, protocol
            ORDER BY bucket ASC
            """,
            (cutoff,),
        )

    def geographic_distribution(self) -> list[dict[str, Any]]:
        return self.db.fetchall(
            """
            SELECT country, country_code, continent, COUNT(*) AS count
            FROM sessions
            WHERE country IS NOT NULL OR country_code IS NOT NULL
            GROUP BY country, country_code, continent
            ORDER BY count DESC
            LIMIT 25
            """
        )

    def recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.db.fetchall(
            """
            SELECT id, timestamp, severity, threat_type, source_ip, description, session_id
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (int(limit),),
        )

    # ------------------------------------------------------------------ #
    # Search helpers (used by the dashboard)
    # ------------------------------------------------------------------ #
    def search_sessions(
        self,
        ip: Optional[str] = None,
        protocol: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self.db.list_sessions(
            ip=ip, protocol=protocol, severity=severity, limit=limit
        )

    def search_alerts(
        self,
        ip: Optional[str] = None,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self.db.list_alerts(
            ip=ip, threat_type=threat_type, severity=severity, limit=limit
        )

    def search_credentials(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ip: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self.db.list_credentials(
            username=username, password=password, ip=ip, limit=limit
        )

    def search_commands(
        self,
        command: Optional[str] = None,
        protocol: Optional[str] = None,
        ip: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self.db.list_commands(
            command=command, protocol=protocol, ip=ip, limit=limit
        )

    def search_http(
        self,
        method: Optional[str] = None,
        path: Optional[str] = None,
        ip: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self.db.list_http_requests(
            method=method, path=path, ip=ip, limit=limit
        )

    def session_details(self, session_id: str) -> dict[str, Any]:
        return self.db.session_details(session_id)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _count(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        row = self.db.fetchone(sql, params)
        if not row:
            return 0
        return int(row.get("c", 0) or 0)
