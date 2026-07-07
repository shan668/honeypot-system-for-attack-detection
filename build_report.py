"""Main service orchestrator for AegisTrap.

The orchestrator wires the configuration, database, logger, session
manager, threat engine and analytics engine into a single runtime. It
owns the listener lifecycles, the background cleanup task, and (when
enabled) the Flask dashboard.
"""

from __future__ import annotations

import signal
import threading
import time
from typing import Optional

from aegistrap.core.analytics import AnalyticsEngine
from aegistrap.core.config import Config, load_config
from aegistrap.core.database import Database
from aegistrap.core.logger import StructuredLogger, get_logger
from aegistrap.core.session import Session, SessionManager
from aegistrap.core.threat_engine import ThreatEngine
from aegistrap.listeners.ftp_listener import FTPListener
from aegistrap.listeners.http_listener import HTTPListener, HTTPSListener
from aegistrap.listeners.ssh_listener import SSHListener
from aegistrap.utils.network import get_local_ip


class AegisTrapService:
    """Top-level runtime that brings up the listeners and dashboard."""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or load_config()
        self.logger = get_logger(
            name="aegistrap",
            log_dir=self.config.logging.directory,
            level=self.config.logging.level,
            max_bytes=self.config.logging.max_bytes,
            backup_count=self.config.logging.backup_count,
            console=self.config.logging.console,
        )
        self.db = Database(
            path=self.config.database.path,
            pool_size=self.config.database.pool_size,
            enable_wal=self.config.database.enable_wal,
        )
        self.threats = ThreatEngine(
            config=self.config.threat,
            database=self.db,
            logger=self.logger,
        )
        self.sessions = SessionManager(
            database=self.db,
            logger=self.logger,
            on_session_closed=self._on_session_closed,
        )
        self.analytics = AnalyticsEngine(self.db)

        self.listeners = {
            "ssh": SSHListener(
                config=self.config,
                database=self.db,
                session_manager=self.sessions,
                threat_engine=self.threats,
                logger=self.logger,
            ),
            "ftp": FTPListener(
                config=self.config,
                database=self.db,
                session_manager=self.sessions,
                threat_engine=self.threats,
                logger=self.logger,
            ),
            "http": HTTPListener(
                config=self.config,
                database=self.db,
                session_manager=self.sessions,
                threat_engine=self.threats,
                logger=self.logger,
            ),
            "https": HTTPSListener(
                config=self.config,
                database=self.db,
                session_manager=self.sessions,
                threat_engine=self.threats,
                logger=self.logger,
            ),
        }

        self._cleanup_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._dashboard_thread: Optional[threading.Thread] = None

        # Register services in DB
        for name, listener in self.listeners.items():
            service_cfg = getattr(self.config, name)
            self.db.upsert_service({
                "name": name,
                "protocol": service_cfg.protocol,
                "enabled": service_cfg.enabled,
                "listen_host": service_cfg.listen_host,
                "listen_port": service_cfg.listen_port,
                "banner": service_cfg.banner,
                "max_concurrent": service_cfg.max_concurrent,
                "started_at": time.time(),
                "status": "starting",
            })

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        """Start the honeypot services."""
        self.logger.info(
            "AegisTrap starting",
            local_ip=get_local_ip(),
            ssh_port=self.config.ssh.listen_port,
            ftp_port=self.config.ftp.listen_port,
            http_port=self.config.http.listen_port,
            https_port=self.config.https.listen_port,
        )
        for name, listener in self.listeners.items():
            service_cfg = getattr(self.config, name)
            if not service_cfg.enabled:
                self.logger.info(f"{name.upper()} listener disabled by config")
                self.db.update_service_status(name, "stopped")
                continue
            listener.start()
            self.db.update_service_status(name, "running")

        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="aegistrap-cleanup",
            daemon=True,
        )
        self._cleanup_thread.start()

        if self.config.dashboard.enabled:
            self._start_dashboard()

        signal.signal(signal.SIGINT, self._on_signal)
        signal.signal(signal.SIGTERM, self._on_signal)

    def wait(self) -> None:
        """Block until interrupted."""
        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=1.0)
        except KeyboardInterrupt:
            self._on_signal(signal.SIGINT, None)

    def stop(self) -> None:
        """Stop the honeypot services."""
        self.logger.info("AegisTrap shutting down")
        self._stop_event.set()
        for name, listener in self.listeners.items():
            try:
                listener.stop()
            except Exception as exc:  # pragma: no cover
                self.logger.error("Listener stop failed", service=name, error=str(exc))
            self.db.update_service_status(name, "stopped")
        if self._cleanup_thread is not None:
            self._cleanup_thread.join(timeout=2.0)
        try:
            self.db.close()
        except Exception:  # pragma: no cover
            pass
        self.logger.shutdown()

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #
    def _cleanup_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                for listener in self.listeners.values():
                    timeout = getattr(listener.config, "session_timeout", 300)
                    if isinstance(timeout, int) and timeout > 0:
                        self.sessions.cleanup_stale(timeout_seconds=timeout * 2)
                self.threats.periodic_cleanup()
            except Exception as exc:  # pragma: no cover
                self.logger.error("Cleanup loop error", error=str(exc))
            self._stop_event.wait(timeout=15)

    def _on_session_closed(self, session: Session) -> None:
        events = self.threats.evaluate_session(session)
        if events:
            max_severity = max((e.severity for e in events), key=self._severity_rank, default="informational")
            self.sessions.set_severity(session.id, max_severity, notes=events[0].description)

    @staticmethod
    def _severity_rank(severity: str) -> int:
        order = {
            "informational": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        return order.get(severity, 0)

    def _on_signal(self, signum: int, frame: object) -> None:  # pragma: no cover
        self.logger.info("Signal received", signal=signum)
        self.stop()

    def _start_dashboard(self) -> None:
        try:
            from aegistrap.dashboard import create_dashboard_app
        except ImportError as exc:
            self.logger.error("Dashboard dependencies missing", error=str(exc))
            return
        app = create_dashboard_app(
            config=self.config,
            database=self.db,
            analytics=self.analytics,
            session_manager=self.sessions,
            threat_engine=self.threats,
            logger=self.logger,
            listeners=self.listeners,
        )
        self._dashboard_app = app

        def _run() -> None:
            self.logger.info(
                "Dashboard started",
                host=self.config.dashboard.host,
                port=self.config.dashboard.port,
            )
            try:
                app.run(
                    host=self.config.dashboard.host,
                    port=self.config.dashboard.port,
                    debug=self.config.dashboard.debug,
                    use_reloader=False,
                    threaded=True,
                )
            except Exception as exc:  # pragma: no cover
                self.logger.error("Dashboard crashed", error=str(exc))

        self._dashboard_thread = threading.Thread(
            target=_run,
            name="aegistrap-dashboard",
            daemon=True,
        )
        self._dashboard_thread.start()
