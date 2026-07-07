"""SQLite persistence layer for AegisTrap.

This module wraps a single ``sqlite3`` connection behind a
thread-safe API. The class is intentionally simple: there is no
ORM and no external driver - the rest of the project only relies on
the Python standard library. The :class:`Database` class manages the
schema, exposes typed insert / update / query helpers, and persists
the high-volume event data captured by the honeypot listeners.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional


SCHEMA_VERSION = 1


SCHEMA_STATEMENTS: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS services (
        name            TEXT PRIMARY KEY,
        protocol        TEXT NOT NULL,
        enabled         INTEGER NOT NULL DEFAULT 1,
        listen_host     TEXT,
        listen_port     INTEGER,
        banner          TEXT,
        max_concurrent  INTEGER,
        started_at      REAL,
        status          TEXT,
        last_status_at  REAL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sessions (
        id              TEXT PRIMARY KEY,
        protocol        TEXT NOT NULL,
        source_ip       TEXT NOT NULL,
        source_port     INTEGER,
        dest_port       INTEGER,
        hostname        TEXT,
        mac_address     TEXT,
        country         TEXT,
        country_code    TEXT,
        city            TEXT,
        isp             TEXT,
        continent       TEXT,
        user_agent      TEXT,
        started_at      REAL NOT NULL,
        ended_at        REAL,
        duration_ms     INTEGER,
        bytes_in        INTEGER DEFAULT 0,
        bytes_out       INTEGER DEFAULT 0,
        outcome         TEXT,
        severity        TEXT DEFAULT 'informational',
        notes           TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON sessions(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON sessions(started_at)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_protocol ON sessions(protocol)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_severity ON sessions(severity)",
    """
    CREATE TABLE IF NOT EXISTS connections (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id      TEXT,
        timestamp       REAL NOT NULL,
        direction       TEXT,
        data_preview    TEXT,
        bytes           INTEGER DEFAULT 0,
        FOREIGN KEY(session_id) REFERENCES sessions(id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_connections_session ON connections(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON connections(timestamp)",
    """
    CREATE TABLE IF NOT EXISTS credentials (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id      TEXT,
        protocol        TEXT NOT NULL,
        username        TEXT,
        password        TEXT,
        success         INTEGER NOT NULL DEFAULT 0,
        attempt_number  INTEGER,
        timestamp       REAL NOT NULL,
        source_ip       TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_credentials_session ON credentials(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_credentials_username ON credentials(username)",
    "CREATE INDEX IF NOT EXISTS idx_credentials_timestamp ON credentials(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_credentials_source_ip ON credentials(source_ip)",
    """
    CREATE TABLE IF NOT EXISTS commands (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id      TEXT,
        protocol        TEXT NOT NULL,
        command         TEXT,
        output          TEXT,
        is_valid        INTEGER DEFAULT 1,
        exit_code       INTEGER,
        timestamp       REAL NOT NULL,
        source_ip       TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_commands_protocol ON commands(protocol)",
    "CREATE INDEX IF NOT EXISTS idx_commands_timestamp ON commands(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_commands_source_ip ON commands(source_ip)",
    """
    CREATE TABLE IF NOT EXISTS ftp_events (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id      TEXT,
        event_type      TEXT,
        command         TEXT,
        argument        TEXT,
        response_code   INTEGER,
        timestamp       REAL NOT NULL,
        source_ip       TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ftp_events_session ON ftp_events(session_id)",
    """
    CREATE TABLE IF NOT EXISTS ssh_events (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id      TEXT,
        event_type      TEXT,
        details         TEXT,
        timestamp       REAL NOT NULL,
        source_ip       TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ssh_events_session ON ssh_events(session_id)",
    """
    CREATE TABLE IF NOT EXISTS http_requests (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id      TEXT,
        timestamp       REAL NOT NULL,
        method          TEXT,
        path            TEXT,
        query           TEXT,
        status_code     INTEGER,
        user_agent      TEXT,
        referrer        TEXT,
        content_type    TEXT,
        content_length  INTEGER,
        source_ip       TEXT,
        body_preview    TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_http_session ON http_requests(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_http_path ON http_requests(path)",
    "CREATE INDEX IF NOT EXISTS idx_http_source_ip ON http_requests(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_http_timestamp ON http_requests(timestamp)",
    """
    CREATE TABLE IF NOT EXISTS files (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id      TEXT,
        action          TEXT,
        filename        TEXT,
        size            INTEGER,
        mime_type       TEXT,
        status          TEXT,
        timestamp       REAL NOT NULL,
        source_ip       TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_files_session ON files(session_id)",
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp       REAL NOT NULL,
        severity        TEXT NOT NULL,
        threat_type     TEXT NOT NULL,
        source_ip       TEXT,
        session_id      TEXT,
        description     TEXT,
        details         TEXT,
        acknowledged    INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_threat_type ON alerts(threat_type)",
    """
    CREATE TABLE IF NOT EXISTS statistics (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp       REAL NOT NULL,
        metric          TEXT NOT NULL,
        value           REAL NOT NULL,
        tag             TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_statistics_metric ON statistics(metric)",
    "CREATE INDEX IF NOT EXISTS idx_statistics_timestamp ON statistics(timestamp)",
    """
    CREATE TABLE IF NOT EXISTS meta (
        key             TEXT PRIMARY KEY,
        value           TEXT
    )
    """,
]


def _row_to_dict(cursor: sqlite3.Cursor, row: Any) -> dict[str, Any]:
    """Convert a ``sqlite3.Row`` (or tuple) row to a ``dict``."""
    if row is None:
        return {}
    if isinstance(row, sqlite3.Row):
        return {key: row[key] for key in row.keys()}
    if cursor.description is None:
        return {}
    columns = [col[0] for col in cursor.description]
    if isinstance(row, (list, tuple)):
        return {col: row[idx] for idx, col in enumerate(columns)}
    return dict(row) if hasattr(row, "items") else {col: row for col in columns}


def _coerce_params(params: Any) -> tuple[Any, ...]:
    """Convert a dict / list of params into a tuple suitable for sqlite."""
    if params is None:
        return ()
    if isinstance(params, tuple):
        return params
    if isinstance(params, (list, dict)):
        return tuple(params)
    return (params,)


class Database:
    """Thread-safe SQLite wrapper for AegisTrap persistence.

    A single connection is used per thread (``check_same_thread=False``
    combined with a re-entrant lock). The class also performs schema
    bootstrap and exposes typed insert / update / query helpers.
    """

    _SESSION_COLS = {
        "id", "protocol", "source_ip", "source_port", "dest_port",
        "hostname", "mac_address", "country", "country_code", "city",
        "isp", "continent", "user_agent", "started_at", "ended_at",
        "duration_ms", "bytes_in", "bytes_out", "outcome", "severity",
        "notes",
    }
    _SERVICE_COLS = {
        "name", "protocol", "enabled", "listen_host", "listen_port",
        "banner", "max_concurrent", "started_at", "status", "last_status_at",
    }
    _CONNECTION_COLS = {"session_id", "timestamp", "direction", "data_preview", "bytes"}
    _CREDENTIAL_COLS = {
        "session_id", "protocol", "username", "password", "success",
        "attempt_number", "timestamp", "source_ip",
    }
    _COMMAND_COLS = {
        "session_id", "protocol", "command", "output", "is_valid",
        "exit_code", "timestamp", "source_ip",
    }
    _FTP_EVENT_COLS = {
        "session_id", "event_type", "command", "argument", "response_code",
        "timestamp", "source_ip",
    }
    _SSH_EVENT_COLS = {"session_id", "event_type", "details", "timestamp", "source_ip"}
    _HTTP_REQ_COLS = {
        "session_id", "timestamp", "method", "path", "query", "status_code",
        "user_agent", "referrer", "content_type", "content_length",
        "source_ip", "body_preview",
    }
    _FILE_COLS = {
        "session_id", "action", "filename", "size", "mime_type", "status",
        "timestamp", "source_ip",
    }
    _ALERT_COLS = {
        "timestamp", "severity", "threat_type", "source_ip", "session_id",
        "description", "details", "acknowledged",
    }

    def __init__(self, path: str, pool_size: int = 5, enable_wal: bool = True) -> None:
        self.path = path
        self.pool_size = max(1, int(pool_size))
        self.enable_wal = bool(enable_wal)
        self._lock = threading.RLock()
        self._local = threading.local()
        self._initialized = False
        self._init_lock = threading.Lock()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn
        target = Path(self.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(target),
            timeout=10.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if self.enable_wal:
            try:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = NORMAL")
            except sqlite3.DatabaseError:
                pass
        self._local.conn = conn
        return conn

    def _ensure_schema(self) -> None:
        if self._initialized:
            return
        with self._init_lock:
            if self._initialized:
                return
            with self._lock:
                conn = self._conn()
                for stmt in SCHEMA_STATEMENTS:
                    conn.execute(stmt)
                conn.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                    ("schema_version", str(SCHEMA_VERSION)),
                )
                self._initialized = True

    def close(self) -> None:
        with self._lock:
            conn = getattr(self._local, "conn", None)
            if conn is not None:
                try:
                    conn.close()
                except sqlite3.DatabaseError:
                    pass
                self._local.conn = None
                self._initialized = False

    def execute(self, sql: str, params: Any = ()) -> sqlite3.Cursor:
        self._ensure_schema()
        with self._lock:
            cur = self._conn().execute(sql, _coerce_params(params))
            return cur

    def executemany(self, sql: str, seq: Any) -> sqlite3.Cursor:
        self._ensure_schema()
        with self._lock:
            cur = self._conn().executemany(sql, list(seq))
            return cur

    def executescript(self, script: str) -> None:
        self._ensure_schema()
        with self._lock:
            self._conn().executescript(script)

    def fetchone(self, sql: str, params: Any = ()) -> Optional[dict[str, Any]]:
        cur = self.execute(sql, params)
        row = cur.fetchone()
        return _row_to_dict(cur, row) if row is not None else None

    def fetchall(self, sql: str, params: Any = ()) -> list[dict[str, Any]]:
        cur = self.execute(sql, params)
        rows = cur.fetchall()
        return [_row_to_dict(cur, row) for row in rows]

    # ------------------------------------------------------------------ #
    # Sessions
    # ------------------------------------------------------------------ #
    def insert_session(self, data: dict[str, Any]) -> None:
        payload = {k: data.get(k) for k in self._SESSION_COLS}
        if not payload.get("id") or not payload.get("protocol") or not payload.get("source_ip"):
            return
        payload.setdefault("started_at", time.time())
        cols = list(payload.keys())
        placeholders = ", ".join(["?"] * len(cols))
        sql = f"INSERT OR REPLACE INTO sessions ({', '.join(cols)}) VALUES ({placeholders})"
        self.execute(sql, [payload[c] for c in cols])

    def update_session(self, session_id: str, fields: dict[str, Any]) -> None:
        if not fields:
            return
        clean = {k: v for k, v in fields.items() if k in self._SESSION_COLS}
        if not clean:
            return
        cols = list(clean.keys())
        set_clause = ", ".join(f"{c} = ?" for c in cols)
        sql = f"UPDATE sessions SET {set_clause} WHERE id = ?"
        params = [clean[c] for c in cols] + [session_id]
        self.execute(sql, params)

    def get_session(self, session_id: str) -> Optional[dict[str, Any]]:
        return self.fetchone("SELECT * FROM sessions WHERE id = ?", (session_id,))

    def list_sessions(
        self,
        ip: Optional[str] = None,
        protocol: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM sessions WHERE 1=1"
        params: list[Any] = []
        if ip:
            sql += " AND source_ip = ?"
            params.append(ip)
        if protocol:
            sql += " AND protocol = ?"
            params.append(protocol)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(int(limit))
        return self.fetchall(sql, params)

    def search_sessions(
        self,
        ip: Optional[str] = None,
        protocol: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self.list_sessions(ip=ip, protocol=protocol, severity=severity, limit=limit)

    def session_details(self, session_id: str) -> dict[str, Any]:
        session = self.get_session(session_id)
        if not session:
            return {}
        credentials = self.fetchall(
            "SELECT * FROM credentials WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )
        commands = self.fetchall(
            "SELECT * FROM commands WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )
        http_requests = self.fetchall(
            "SELECT * FROM http_requests WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )
        ftp_events = self.fetchall(
            "SELECT * FROM ftp_events WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )
        ssh_events = self.fetchall(
            "SELECT * FROM ssh_events WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )
        files = self.fetchall(
            "SELECT * FROM files WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )
        alerts = self.fetchall(
            "SELECT * FROM alerts WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )
        return {
            "session": session,
            "credentials": credentials,
            "commands": commands,
            "http_requests": http_requests,
            "ftp_events": ftp_events,
            "ssh_events": ssh_events,
            "files": files,
            "alerts": alerts,
        }

    # ------------------------------------------------------------------ #
    # Services
    # ------------------------------------------------------------------ #
    def upsert_service(self, data: dict[str, Any]) -> None:
        payload = {k: data.get(k) for k in self._SERVICE_COLS}
        if not payload.get("name"):
            return
        payload.setdefault("last_status_at", time.time())
        cols = list(payload.keys())
        placeholders = ", ".join(["?"] * len(cols))
        update_clause = ", ".join(f"{c} = excluded.{c}" for c in cols if c != "name")
        sql = (
            f"INSERT INTO services ({', '.join(cols)}) VALUES ({placeholders}) "
            f"ON CONFLICT(name) DO UPDATE SET {update_clause}"
        )
        self.execute(sql, [payload[c] for c in cols])

    def update_service_status(self, name: str, status: str) -> None:
        self.execute(
            "UPDATE services SET status = ?, last_status_at = ? WHERE name = ?",
            (status, time.time(), name),
        )

    def list_services(self) -> list[dict[str, Any]]:
        return self.fetchall("SELECT * FROM services ORDER BY name")

    # ------------------------------------------------------------------ #
    # Connections
    # ------------------------------------------------------------------ #
    def record_connection(self, data: dict[str, Any]) -> None:
        payload = {k: data.get(k) for k in self._CONNECTION_COLS}
        if "timestamp" not in payload:
            payload["timestamp"] = time.time()
        cols = list(payload.keys())
        placeholders = ", ".join(["?"] * len(cols))
        sql = f"INSERT INTO connections ({', '.join(cols)}) VALUES ({placeholders})"
        self.execute(sql, [payload[c] for c in cols])

    # ------------------------------------------------------------------ #
    # Credentials
    # ------------------------------------------------------------------ #
    def record_credential(self, data: dict[str, Any]) -> None:
        payload = {k: data.get(k) for k in self._CREDENTIAL_COLS}
        payload.setdefault("timestamp", time.time())
        payload.setdefault("success", 0)
        payload["success"] = 1 if payload.get("success") else 0
        cols = list(payload.keys())
        placeholders = ", ".join(["?"] * len(cols))
        sql = f"INSERT INTO credentials ({', '.join(cols)}) VALUES ({placeholders})"
        self.execute(sql, [payload[c] for c in cols])

    def list_credentials(
        self,
        session_id: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ip: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM credentials WHERE 1=1"
        params: list[Any] = []
        if session_id:
            sql += " AND session_id = ?"
            params.append(session_id)
        if username:
            sql += " AND username LIKE ?"
            params.append(f"%{username}%")
        if password:
            sql += " AND password LIKE ?"
            params.append(f"%{password}%")
        if ip:
            sql += " AND source_ip = ?"
            params.append(ip)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(int(limit))
        return self.fetchall(sql, params)

    def search_credentials(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ip: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self.list_credentials(
            username=username, password=password, ip=ip, limit=limit
        )

    # ------------------------------------------------------------------ #
    # Commands
    # ------------------------------------------------------------------ #
    def record_command(self, data: dict[str, Any]) -> None:
        payload = {k: data.get(k) for k in self._COMMAND_COLS}
        payload.setdefault("timestamp", time.time())
        payload.setdefault("is_valid", 1)
        payload["is_valid"] = 1 if payload.get("is_valid") else 0
        cols = list(payload.keys())
        placeholders = ", ".join(["?"] * len(cols))
        sql = f"INSERT INTO commands ({', '.join(cols)}) VALUES ({placeholders})"
        self.execute(sql, [payload[c] for c in cols])

    def list_commands(
        self,
        session_id: Optional[str] = None,
        command: Optional[str] = None,
        protocol: Optional[str] = None,
        ip: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM commands WHERE 1=1"
        params: list[Any] = []
        if session_id:
            sql += " AND session_id = ?"
            params.append(session_id)
        if command:
            sql += " AND command LIKE ?"
            params.append(f"%{command}%")
        if protocol:
            sql += " AND protocol = ?"
            params.append(protocol)
        if ip:
            sql += " AND source_ip = ?"
            params.append(ip)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(int(limit))
        return self.fetchall(sql, params)

    def search_commands(
        self,
        command: Optional[str] = None,
        protocol: Optional[str] = None,
        ip: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self.list_commands(
            command=command, protocol=protocol, ip=ip, limit=limit
        )

    # ------------------------------------------------------------------ #
    # FTP events
    # ------------------------------------------------------------------ #
    def record_ftp_event(self, data: dict[str, Any]) -> None:
        payload = {k: data.get(k) for k in self._FTP_EVENT_COLS}
        payload.setdefault("timestamp", time.time())
        cols = list(payload.keys())
        placeholders = ", ".join(["?"] * len(cols))
        sql = f"INSERT INTO ftp_events ({', '.join(cols)}) VALUES ({placeholders})"
        self.execute(sql, [payload[c] for c in cols])

    def list_ftp_events(self, session_id: str) -> list[dict[str, Any]]:
        return self.fetchall(
            "SELECT * FROM ftp_events WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )

    # ------------------------------------------------------------------ #
    # SSH events
    # ------------------------------------------------------------------ #
    def record_ssh_event(self, data: dict[str, Any]) -> None:
        payload = {k: data.get(k) for k in self._SSH_EVENT_COLS}
        details = payload.get("details")
        if isinstance(details, (dict, list)):
            payload["details"] = json.dumps(details)
        payload.setdefault("timestamp", time.time())
        cols = list(payload.keys())
        placeholders = ", ".join(["?"] * len(cols))
        sql = f"INSERT INTO ssh_events ({', '.join(cols)}) VALUES ({placeholders})"
        self.execute(sql, [payload[c] for c in cols])

    def list_ssh_events(self, session_id: str) -> list[dict[str, Any]]:
        return self.fetchall(
            "SELECT * FROM ssh_events WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )

    # ------------------------------------------------------------------ #
    # HTTP requests
    # ------------------------------------------------------------------ #
    def record_http_request(self, data: dict[str, Any]) -> None:
        payload = {k: data.get(k) for k in self._HTTP_REQ_COLS}
        payload.setdefault("timestamp", time.time())
        cols = list(payload.keys())
        placeholders = ", ".join(["?"] * len(cols))
        sql = f"INSERT INTO http_requests ({', '.join(cols)}) VALUES ({placeholders})"
        self.execute(sql, [payload[c] for c in cols])

    def list_http_requests(
        self,
        session_id: Optional[str] = None,
        method: Optional[str] = None,
        path: Optional[str] = None,
        ip: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM http_requests WHERE 1=1"
        params: list[Any] = []
        if session_id:
            sql += " AND session_id = ?"
            params.append(session_id)
        if method:
            sql += " AND method = ?"
            params.append(method)
        if path:
            sql += " AND path LIKE ?"
            params.append(f"%{path}%")
        if ip:
            sql += " AND source_ip = ?"
            params.append(ip)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(int(limit))
        return self.fetchall(sql, params)

    def search_http(
        self,
        method: Optional[str] = None,
        path: Optional[str] = None,
        ip: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self.list_http_requests(
            method=method, path=path, ip=ip, limit=limit
        )

    # ------------------------------------------------------------------ #
    # Files
    # ------------------------------------------------------------------ #
    def record_file(self, data: dict[str, Any]) -> None:
        payload = {k: data.get(k) for k in self._FILE_COLS}
        payload.setdefault("timestamp", time.time())
        cols = list(payload.keys())
        placeholders = ", ".join(["?"] * len(cols))
        sql = f"INSERT INTO files ({', '.join(cols)}) VALUES ({placeholders})"
        self.execute(sql, [payload[c] for c in cols])

    def list_files(self, session_id: str) -> list[dict[str, Any]]:
        return self.fetchall(
            "SELECT * FROM files WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )

    # ------------------------------------------------------------------ #
    # Alerts
    # ------------------------------------------------------------------ #
    def insert_alert(self, event: Any) -> None:
        details = getattr(event, "details", None)
        if isinstance(details, (dict, list)):
            details_json = json.dumps(details)
        else:
            details_json = details
        payload = {
            "timestamp": getattr(event, "timestamp", time.time()),
            "severity": getattr(event, "severity", "informational"),
            "threat_type": getattr(event, "threat_type", "unknown"),
            "source_ip": getattr(event, "source_ip", None),
            "session_id": getattr(event, "session_id", None),
            "description": getattr(event, "description", ""),
            "details": details_json,
        }
        cols = list(payload.keys())
        placeholders = ", ".join(["?"] * len(cols))
        sql = f"INSERT INTO alerts ({', '.join(cols)}) VALUES ({placeholders})"
        self.execute(sql, [payload[c] for c in cols])

    def list_alerts(
        self,
        ip: Optional[str] = None,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []
        if ip:
            sql += " AND source_ip = ?"
            params.append(ip)
        if threat_type:
            sql += " AND threat_type = ?"
            params.append(threat_type)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(int(limit))
        return self.fetchall(sql, params)

    def search_alerts(
        self,
        ip: Optional[str] = None,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return self.list_alerts(
            ip=ip, threat_type=threat_type, severity=severity, limit=limit
        )

    def acknowledge_alert(self, alert_id: int) -> None:
        self.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
            (int(alert_id),),
        )

    # ------------------------------------------------------------------ #
    # Statistics
    # ------------------------------------------------------------------ #
    def record_statistic(self, metric: str, value: float, tag: Optional[str] = None) -> None:
        self.execute(
            "INSERT INTO statistics (timestamp, metric, value, tag) VALUES (?, ?, ?, ?)",
            (time.time(), metric, float(value), tag),
        )

    def list_statistics(self, metric: str, limit: int = 100) -> list[dict[str, Any]]:
        return self.fetchall(
            "SELECT * FROM statistics WHERE metric = ? ORDER BY timestamp DESC LIMIT ?",
            (metric, int(limit)),
        )

    def clear_captured_data(self) -> dict[str, int]:
        """Delete captured honeypot activity while keeping service config rows."""
        tables = [
            "connections",
            "credentials",
            "commands",
            "ftp_events",
            "ssh_events",
            "http_requests",
            "files",
            "alerts",
            "statistics",
            "sessions",
        ]
        deleted: dict[str, int] = {}
        with self._lock:
            conn = self._conn()
            self._ensure_schema()
            for table in tables:
                cur = conn.execute(f"DELETE FROM {table}")
                deleted[table] = int(cur.rowcount if cur.rowcount is not None else 0)
            conn.execute("VACUUM")
        return deleted
