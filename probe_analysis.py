"""FTP listener binding for AegisTrap."""

from __future__ import annotations

from aegistrap.core.config import Config
from aegistrap.core.database import Database
from aegistrap.core.logger import StructuredLogger
from aegistrap.core.session import SessionManager
from aegistrap.core.threat_engine import ThreatEngine
from aegistrap.listeners.base import ServiceListener
from aegistrap.protocols.ftp import FTPEmulator


class FTPListener(ServiceListener):
    def __init__(
        self,
        config: Config,
        database: Database,
        session_manager: SessionManager,
        threat_engine: ThreatEngine,
        logger: StructuredLogger,
    ) -> None:
        emulator = FTPEmulator(
            config=config,
            database=database,
            session_manager=session_manager,
            threat_engine=threat_engine,
            logger=logger,
        )
        super().__init__(
            service_config=config.ftp,
            logger=logger,
            connection_handler=emulator.handle_connection,
        )
        self.emulator = emulator

