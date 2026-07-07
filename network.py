"""Base service listener for AegisTrap.

A :class:`ServiceListener` wraps a TCP socket and a worker thread. The
subclass implements :meth:`handle_connection` for its protocol. The
listener provides automatic restart, graceful shutdown, and a
semaphore-backed concurrency limit.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Any, Callable, Optional

from aegistrap.core.config import ServiceConfig
from aegistrap.core.logger import StructuredLogger


class ServiceListener:
    """Base class for service listeners."""

    def __init__(
        self,
        service_config: ServiceConfig,
        logger: StructuredLogger,
        connection_handler: Callable[[socket.socket, tuple[str, int], ServiceConfig], None],
    ) -> None:
        self.config = service_config
        self.logger = logger
        self.handler = connection_handler
        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._semaphore = threading.BoundedSemaphore(service_config.max_concurrent)
        self._active_workers = 0
        self._active_lock = threading.Lock()
        self._restart_attempts = 0
        self._max_restart_attempts = 10
        self._restart_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        """Start the listener in a background thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._serve_forever_with_restart,
            name=f"listener-{self.config.name}",
            daemon=True,
        )
        self._thread.start()
        self.logger.info(
            f"{self.config.name.upper()} listener started",
            host=self.config.listen_host,
            port=self.config.listen_port,
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Stop accepting new connections."""
        self._stop_event.set()
        try:
            if self._server_socket is not None:
                self._server_socket.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self.logger.info(f"{self.config.name.upper()} listener stopped")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

    @property
    def active_connections(self) -> int:
        with self._active_lock:
            return self._active_workers

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _serve_forever_with_restart(self) -> None:
        backoff = 1.0
        while not self._stop_event.is_set():
            try:
                self._serve_forever()
                backoff = 1.0
            except Exception as exc:  # pragma: no cover - defensive
                with self._restart_lock:
                    self._restart_attempts += 1
                self.logger.error(
                    f"{self.config.name} listener crashed",
                    error=str(exc),
                    attempt=self._restart_attempts,
                )
                if self._restart_attempts > self._max_restart_attempts:
                    self.logger.critical(
                        f"{self.config.name} exceeded max restart attempts; giving up"
                    )
                    return
                if self._stop_event.wait(timeout=backoff):
                    return
                backoff = min(backoff * 2, 30.0)

    def _serve_forever(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config.listen_host, self.config.listen_port))
        sock.listen(128)
        sock.settimeout(1.0)
        self._server_socket = sock
        self._restart_attempts = 0
        self.logger.info(
            f"{self.config.name.upper()} listening",
            host=self.config.listen_host,
            port=self.config.listen_port,
        )
        try:
            while not self._stop_event.is_set():
                try:
                    client_sock, client_addr = sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop_event.is_set():
                        return
                    raise
                self._semaphore.acquire()
                thread = threading.Thread(
                    target=self._safe_handle,
                    args=(client_sock, client_addr),
                    name=f"{self.config.name}-{client_addr[0]}:{client_addr[1]}",
                    daemon=True,
                )
                thread.start()
        finally:
            try:
                sock.close()
            except OSError:
                pass
            self._server_socket = None

    def _safe_handle(self, client_sock: socket.socket, client_addr: tuple[str, int]) -> None:
        with self._active_lock:
            self._active_workers += 1
        try:
            self.handler(client_sock, client_addr, self.config)
        except Exception as exc:  # pragma: no cover
            self.logger.error(
                f"{self.config.name} handler crashed",
                error=str(exc),
                peer=f"{client_addr[0]}:{client_addr[1]}",
            )
        finally:
            with self._active_lock:
                self._active_workers = max(0, self._active_workers - 1)
            try:
                client_sock.close()
            except OSError:
                pass
            try:
                self._semaphore.release()
            except ValueError:
                pass

