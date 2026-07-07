"""Structured JSON logging engine for AegisTrap.

This module provides a thread-safe structured logger that writes
JSON-formatted log records to rotating files and (optionally) the
console. The format is consistent across the platform so external log
ingestors (e.g. ELK, Splunk) can consume it directly.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

_LOGGERS: dict[str, "StructuredLogger"] = {}
_LOCK = threading.Lock()


class JsonFormatter(logging.Formatter):
    """Format log records as compact single-line JSON."""

    def __init__(self, project: str = "aegistrap") -> None:
        super().__init__()
        self.project = project

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "project": self.project,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra_fields"):
            payload.update(record.extra_fields)  # type: ignore[arg-type]
        # Promote all custom attributes attached to the record
        for key, value in record.__dict__.items():
            if key in (
                "args", "asctime", "created", "exc_info", "exc_text", "filename",
                "funcName", "levelname", "levelno", "lineno", "module", "msecs",
                "message", "msg", "name", "pathname", "process", "processName",
                "relativeCreated", "stack_info", "thread", "threadName",
                "taskName", "extra_fields",
            ):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)
        return json.dumps(payload, ensure_ascii=False, default=str)


class StructuredLogger:
    """High-level wrapper that exposes helper methods for common events."""

    def __init__(
        self,
        name: str,
        log_dir: str,
        level: str = "INFO",
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 10,
        console: bool = True,
    ) -> None:
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._stop_event = threading.Event()
        self._listener: Optional[logging.handlers.QueueListener] = None

        self._logger = logging.getLogger(name)
        self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        self._logger.propagate = False

        # Remove pre-existing handlers to avoid double logging
        for handler in list(self._logger.handlers):
            self._logger.removeHandler(handler)

        self._queue_handler = logging.handlers.QueueHandler(self._log_queue)
        self._logger.addHandler(self._queue_handler)

        formatter = JsonFormatter()
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / f"{name}.log",
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        handlers: list[logging.Handler] = [file_handler]

        if console:
            stream = logging.StreamHandler(sys.stdout)
            stream.setFormatter(formatter)
            handlers.append(stream)

        self._listener_handlers = handlers
        self._listener = logging.handlers.QueueListener(
            self._log_queue, *handlers, respect_handler_level=True
        )
        self._listener.start()

    # ------------------------------------------------------------------ #
    # Standard logging passthroughs
    # ------------------------------------------------------------------ #
    def debug(self, message: str, **fields: Any) -> None:
        self._log(logging.DEBUG, message, fields)

    def info(self, message: str, **fields: Any) -> None:
        self._log(logging.INFO, message, fields)

    def warning(self, message: str, **fields: Any) -> None:
        self._log(logging.WARNING, message, fields)

    def error(self, message: str, **fields: Any) -> None:
        self._log(logging.ERROR, message, fields)

    def critical(self, message: str, **fields: Any) -> None:
        self._log(logging.CRITICAL, message, fields)

    def exception(self, message: str, **fields: Any) -> None:
        self._logger.exception(message, extra={"extra_fields": fields})

    def log_event(self, event_type: str, **fields: Any) -> None:
        """Emit a structured event log line (e.g. ``protocol.event``)."""
        payload = {"event_type": event_type, "category": "event"}
        payload.update(fields)
        self._log(logging.INFO, event_type, payload)

    def log_alert(self, severity: str, threat_type: str, **fields: Any) -> None:
        """Emit an alert log line."""
        payload = {"category": "alert", "severity": severity, "threat_type": threat_type}
        payload.update(fields)
        self._log(logging.WARNING, f"alert.{threat_type}", payload)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _log(self, level: int, message: str, fields: dict[str, Any]) -> None:
        self._logger.log(level, message, extra={"extra_fields": fields})

    def shutdown(self) -> None:
        if self._listener is not None:
            self._listener.stop()
        for handler in getattr(self, "_listener_handlers", []):
            try:
                handler.close()
            except Exception:
                pass
        for handler in list(self._logger.handlers):
            self._logger.removeHandler(handler)
        self._logger.handlers.clear()


def get_logger(
    name: str = "aegistrap",
    log_dir: str = "logs",
    level: str = "INFO",
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 10,
    console: bool = True,
) -> StructuredLogger:
    """Return a cached :class:`StructuredLogger` instance.

    Subsequent calls with the same ``name`` return the same logger
    so that log handlers are not duplicated.
    """
    with _LOCK:
        existing = _LOGGERS.get(name)
        if existing is not None:
            return existing
        logger = StructuredLogger(
            name=name,
            log_dir=log_dir,
            level=level,
            max_bytes=max_bytes,
            backup_count=backup_count,
            console=console,
        )
        _LOGGERS[name] = logger
        return logger
