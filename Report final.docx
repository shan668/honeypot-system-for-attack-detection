"""HTTP listener binding for AegisTrap."""

from __future__ import annotations

import socket
import socketserver
import ssl
import threading
from pathlib import Path
from typing import Any

from aegistrap.core.config import Config
from aegistrap.core.database import Database
from aegistrap.core.logger import StructuredLogger
from aegistrap.core.session import SessionManager
from aegistrap.core.threat_engine import ThreatEngine
from aegistrap.listeners.base import ServiceListener
from aegistrap.protocols.http import HTTPEmulator

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as _dt
except ImportError:  # pragma: no cover
    x509 = None  # type: ignore[assignment]


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Multi-threaded HTTP server used by the HTTP listener."""

    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


class HTTPListener(ServiceListener):
    """Binds an HTTP honeypot to the configured interface and port."""

    def __init__(
        self,
        config: Config,
        database: Database,
        session_manager: SessionManager,
        threat_engine: ThreatEngine,
        logger: StructuredLogger,
    ) -> None:
        self.config = config
        self.service_config = config.http
        self.service_name = "http"
        self.use_tls = False
        self.logger = logger
        self.database = database
        self.sessions = session_manager
        self.threats = threat_engine
        self._server: _ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._active_workers = 0
        self._active_lock = threading.Lock()

        emulator = HTTPEmulator(
            config=config,
            database=database,
            session_manager=session_manager,
            threat_engine=threat_engine,
            logger=logger,
        )
        handler_cls = emulator.build_handler()

        class _BoundHandler(handler_cls):
            listener = self  # type: ignore[assignment]

            def handle(self) -> None:  # type: ignore[override]
                with self.listener._active_lock:
                    self.listener._active_workers += 1
                try:
                    super().handle()
                finally:
                    with self.listener._active_lock:
                        self.listener._active_workers = max(0, self.listener._active_workers - 1)

        self._handler_cls = _BoundHandler
        self.emulator = emulator

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._serve_forever_with_restart,
            name=f"listener-{self.service_name}",
            daemon=True,
        )
        self._thread.start()
        self.logger.info(
            f"{self.service_name.upper()} listener started",
            host=self.service_config.listen_host,
            port=self.service_config.listen_port,
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._server is not None:
            try:
                self._server.shutdown()
            except Exception:  # pragma: no cover
                pass
            try:
                self._server.server_close()
            except Exception:  # pragma: no cover
                pass
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self.logger.info(f"{self.service_name.upper()} listener stopped")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

    @property
    def active_connections(self) -> int:
        with self._active_lock:
            return self._active_workers

    def _serve_forever_with_restart(self) -> None:
        backoff = 1.0
        attempts = 0
        max_attempts = 10
        while not self._stop_event.is_set():
            try:
                self._serve_forever()
                backoff = 1.0
                attempts = 0
            except Exception as exc:  # pragma: no cover
                attempts += 1
                self.logger.error(f"{self.service_name.upper()} listener crashed", error=str(exc), attempt=attempts)
                if attempts > max_attempts:
                    self.logger.critical(f"{self.service_name.upper()} listener giving up after too many restarts")
                    return
                if self._stop_event.wait(timeout=backoff):
                    return
                backoff = min(backoff * 2, 30.0)

    def _serve_forever(self) -> None:
        server = _ThreadingHTTPServer(
            (self.service_config.listen_host, self.service_config.listen_port),
            self._handler_cls,
        )
        if self.use_tls:
            context = _tls_context()
            server.socket = context.wrap_socket(server.socket, server_side=True)
        self._server = server
        self.logger.info(
            f"{self.service_name.upper()} listening",
            host=self.service_config.listen_host,
            port=self.service_config.listen_port,
        )
        try:
            server.serve_forever(poll_interval=0.5)
        finally:
            try:
                server.server_close()
            except OSError:
                pass
            self._server = None


class HTTPSListener(HTTPListener):
    """HTTPS wrapper around the HTTP honeypot application."""

    def __init__(
        self,
        config: Config,
        database: Database,
        session_manager: SessionManager,
        threat_engine: ThreatEngine,
        logger: StructuredLogger,
    ) -> None:
        super().__init__(config, database, session_manager, threat_engine, logger)
        self.service_config = config.https
        self.service_name = "https"
        self.use_tls = True


def _tls_context() -> ssl.SSLContext:
    cert_path, key_path = _ensure_self_signed_cert()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context


def _ensure_self_signed_cert() -> tuple[Path, Path]:
    cert_dir = Path("config") / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "aegistrap_https.crt"
    key_path = cert_dir / "aegistrap_https.key"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path
    if x509 is None:
        raise RuntimeError("cryptography is required to generate HTTPS certificates")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AegisTrap Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "edge-router-01"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(days=1))
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("edge-router-01")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path
