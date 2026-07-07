"""Configuration management for AegisTrap.

This module loads, validates and exposes runtime configuration. The
configuration is sourced from a YAML file (``config/config.yaml`` by
default) and may be overridden with environment variables prefixed
``AEGISTRAP_``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    yaml = None  # type: ignore


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "config.yaml"


@dataclass
class ServiceConfig:
    """Configuration for an individual honeypot service."""

    name: str
    protocol: str
    enabled: bool = True
    listen_host: str = "0.0.0.0"
    listen_port: int = 0
    banner: str = ""
    max_concurrent: int = 50
    session_timeout: int = 300


@dataclass
class DashboardConfig:
    """Configuration for the Flask analytics dashboard."""

    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 5000
    secret_key: str = ""
    debug: bool = False
    refresh_interval_ms: int = 5000


@dataclass
class LoggingConfig:
    """Configuration for structured JSON logging."""

    directory: str = "logs"
    level: str = "INFO"
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 10
    console: bool = True


@dataclass
class DatabaseConfig:
    """Configuration for the SQLite database."""

    path: str = "data/aegistrap.db"
    pool_size: int = 5
    enable_wal: bool = True


@dataclass
class ThreatConfig:
    """Configuration for the threat intelligence engine."""

    # Sliding window in seconds
    window_seconds: int = 60
    # Threshold for failed login attempts
    failed_login_threshold: int = 5
    # Threshold for high-frequency requests
    request_rate_threshold: int = 100
    # Threshold for unique paths probed (directory brute-force)
    directory_bruteforce_threshold: int = 30
    # Threshold for unique usernames tried (password spraying)
    unique_user_threshold: int = 10
    # Threshold for distinct credentials per source IP
    credential_stuffing_threshold: int = 15
    # Threshold for SSH commands per session
    ssh_command_threshold: int = 50
    # Threshold for FTP commands per session
    ftp_command_threshold: int = 100
    # Auto-block threshold (informational only, no real blocking)
    auto_block_threshold: int = 200


@dataclass
class Config:
    """Top-level configuration container."""

    general: dict[str, Any] = field(default_factory=lambda: {
        "project_name": "AegisTrap",
        "version": "1.0.0",
        "log_level": "INFO",
    })
    ssh: ServiceConfig = field(default_factory=lambda: ServiceConfig(
        name="ssh",
        protocol="ssh",
        enabled=True,
        listen_host="0.0.0.0",
        listen_port=2222,
        banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        max_concurrent=50,
        session_timeout=300,
    ))
    ftp: ServiceConfig = field(default_factory=lambda: ServiceConfig(
        name="ftp",
        protocol="ftp",
        enabled=True,
        listen_host="0.0.0.0",
        listen_port=2121,
        banner="vsftpd 3.0.5",
        max_concurrent=50,
        session_timeout=300,
    ))
    http: ServiceConfig = field(default_factory=lambda: ServiceConfig(
        name="http",
        protocol="http",
        enabled=True,
        listen_host="0.0.0.0",
        listen_port=8080,
        banner="Apache/2.4.57 (Ubuntu)",
        max_concurrent=100,
        session_timeout=120,
    ))
    https: ServiceConfig = field(default_factory=lambda: ServiceConfig(
        name="https",
        protocol="https",
        enabled=True,
        listen_host="0.0.0.0",
        listen_port=8443,
        banner="Apache/2.4.57 (Ubuntu)",
        max_concurrent=100,
        session_timeout=120,
    ))
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    threat: ThreatConfig = field(default_factory=ThreatConfig)
    fake_users: list[str] = field(default_factory=lambda: [
        "root", "admin", "user", "test", "ubuntu", "pi", "oracle",
        "postgres", "ftpuser", "guest", "support", "administrator",
        "service", "webmaster", "student", "info", "marketing",
    ])
    fake_passwords: list[str] = field(default_factory=lambda: [
        "admin", "password", "123456", "root", "toor", "letmein",
        "qwerty", "P@ssw0rd", "changeme", "welcome", "test",
        "default", "12345", "alpine", "raspberry", "ubuntu",
    ])
    fake_hostname: str = "edge-router-01"
    # When True the FTP service accepts any credentials with ``230 Login
    # successful`` so standard clients (FileZilla, curl, lftp) proceed past
    # authentication and reveal post-login behaviour. When False the service
    # always replies ``530 Login incorrect`` (credentials are still captured).
    ftp_accept_login: bool = True
    # Hard ceiling on a single FTP/SFTP upload captured into the virtual
    # filesystem. Prevents an attacker from exhausting honeypot memory.
    ftp_max_upload_bytes: int = 10 * 1024 * 1024
    fake_filelist: list[dict[str, str]] = field(default_factory=lambda: [
        {"name": "README.md", "size": "1024", "type": "file"},
        {"name": "backup.tar.gz", "size": "2097152", "type": "file"},
        {"name": "logs", "size": "0", "type": "dir"},
        {"name": "configs", "size": "0", "type": "dir"},
        {"name": "data", "size": "0", "type": "dir"},
        {"name": "scripts", "size": "0", "type": "dir"},
    ])

    def to_dict(self) -> dict[str, Any]:
        """Return a dictionary representation."""
        return asdict(self)


def _coerce_service(data: dict[str, Any]) -> ServiceConfig:
    """Build a :class:`ServiceConfig` from a plain dict."""
    return ServiceConfig(
        name=data.get("name", "unknown"),
        protocol=data.get("protocol", "tcp"),
        enabled=bool(data.get("enabled", True)),
        listen_host=data.get("listen_host", "0.0.0.0"),
        listen_port=int(data.get("listen_port", 0)),
        banner=str(data.get("banner", "")),
        max_concurrent=int(data.get("max_concurrent", 50)),
        session_timeout=int(data.get("session_timeout", 300)),
    )


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    """Load configuration from a YAML file, with environment overrides.

    Args:
        path: Optional path to a YAML configuration file. When omitted,
            ``config/config.yaml`` next to the project root is used.

    Returns:
        A fully-populated :class:`Config` instance.
    """
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    data: dict[str, Any] = {}

    if cfg_path.exists():
        with cfg_path.open("r", encoding="utf-8") as handle:
            text = handle.read()
        if yaml is not None:
            data = yaml.safe_load(text) or {}
        else:
            data = _minimal_yaml_load(text)

    config = Config()

    # General
    if "general" in data and isinstance(data["general"], dict):
        config.general.update(data["general"])

    # Services
    for service_key in ("ssh", "ftp", "http", "https"):
        section = data.get(service_key)
        if isinstance(section, dict):
            merged = asdict(getattr(config, service_key))
            merged.update(section)
            setattr(config, service_key, _coerce_service(merged))

    # Dashboard
    if "dashboard" in data and isinstance(data["dashboard"], dict):
        for key, value in data["dashboard"].items():
            if hasattr(config.dashboard, key):
                setattr(config.dashboard, key, value)

    # Logging
    if "logging" in data and isinstance(data["logging"], dict):
        for key, value in data["logging"].items():
            if hasattr(config.logging, key):
                setattr(config.logging, key, value)

    # Database
    if "database" in data and isinstance(data["database"], dict):
        for key, value in data["database"].items():
            if hasattr(config.database, key):
                setattr(config.database, key, value)

    # Threat engine
    if "threat" in data and isinstance(data["threat"], dict):
        for key, value in data["threat"].items():
            if hasattr(config.threat, key):
                setattr(config.threat, key, value)

    # Lists / strings
    for key in ("fake_users", "fake_passwords", "fake_filelist"):
        if key in data and isinstance(data[key], list):
            setattr(config, key, list(data[key]))

    for key in ("fake_hostname",):
        if key in data and isinstance(data[key], str):
            setattr(config, key, data[key])

    if "ftp_accept_login" in data:
        config.ftp_accept_login = bool(data["ftp_accept_login"])
    if "ftp_max_upload_bytes" in data:
        try:
            config.ftp_max_upload_bytes = int(data["ftp_max_upload_bytes"])
        except (TypeError, ValueError):
            pass

    # Environment overrides (e.g. AEGISTRAP_SSH_LISTEN_PORT=2222)
    for key, value in os.environ.items():
        if not key.startswith("AEGISTRAP_"):
            continue
        parts = key[len("AEGISTRAP_"):].lower().split("_")
        if not parts:
            continue
        section = parts[0]
        attr = "_".join(parts[1:]) if len(parts) > 1 else None
        if attr is None:
            continue
        target = None
        if section in ("ssh", "ftp", "http"):
            target = getattr(config, section)
        elif section == "dashboard":
            target = config.dashboard
        elif section == "logging":
            target = config.logging
        elif section == "database":
            target = config.database
        elif section == "threat":
            target = config.threat
        if target is not None and hasattr(target, attr):
            current = getattr(target, attr)
            if isinstance(current, bool):
                setattr(target, attr, value.lower() in ("1", "true", "yes", "on"))
            elif isinstance(current, int):
                try:
                    setattr(target, attr, int(value))
                except ValueError:
                    pass
            else:
                setattr(target, attr, value)

    return config


def save_config(config: Config, path: str | os.PathLike[str]) -> None:
    """Write a :class:`Config` to a YAML file.

    Falls back to a minimal serialiser when PyYAML is not installed so
    the configuration can still be persisted for inspection.

    Args:
        config: The configuration object to serialise.
        path: Destination path.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = config.to_dict()

    with target.open("w", encoding="utf-8") as handle:
        handle.write(f"# AegisTrap configuration\n# Generated automatically\n\n")
        if yaml is not None:
            yaml.safe_dump(payload, handle, sort_keys=False, default_flow_style=False)
        else:
            _minimal_yaml_dump(payload, handle)


def _minimal_yaml_load(text: str) -> dict[str, Any]:
    """Parse a small subset of YAML without external dependencies.

    Supports the constructs used by the bundled configuration file:
    nested mappings, lists, booleans, integers and strings.

    Args:
        text: YAML text content.

    Returns:
        A dictionary representation of the YAML.
    """
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    pending_key: Optional[str] = None
    pending_indent: int = -1
    list_index: dict[int, int] = {}

    def coerce(value: str) -> Any:
        value = value.strip()
        if not value:
            return ""
        if value.lower() in ("true", "yes", "on"):
            return True
        if value.lower() in ("false", "no", "off"):
            return False
        if value.lower() in ("null", "~", ""):
            return None
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            return value[1:-1]
        try:
            return int(value)
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            pass
        return value

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        content = line.strip()

        # Pop stack to current indent
        while stack and stack[-1][0] >= indent and stack[-1][0] != -1:
            stack.pop()
        if not stack:
            stack = [(-1, root)]
        parent = stack[-1][1]

        if content.startswith("- "):
            value = content[2:].strip()
            if isinstance(parent, list):
                item: Any = coerce(value) if value else {}
                if not value:
                    parent.append({})
                    item = parent[-1]
                    new_indent = indent + 2
                    stack.append((indent, item))
                    list_index[id(parent)] = len(parent)
                else:
                    parent.append(item)
            continue

        if ":" in content:
            key, _, value = content.partition(":")
            key = key.strip()
            value = value.strip()
            if isinstance(parent, dict):
                if not value:
                    # Could be a nested mapping or list
                    # Peek next non-empty line
                    if key not in parent:
                        parent[key] = {}
                    if isinstance(parent[key], dict):
                        stack.append((indent, parent[key]))
                else:
                    parent[key] = coerce(value)
            pending_key = key
            pending_indent = indent
        elif content.startswith("-") and not content.startswith("--"):
            if isinstance(parent, list):
                parent.append(coerce(content[1:].strip()))
        else:
            # Continuation of previous key
            if pending_key is not None and isinstance(parent, dict):
                parent[pending_key] = coerce(content)
                pending_key = None

    return root


def _minimal_yaml_dump(data: Any, handle: Any, indent: int = 0) -> None:
    """Minimal YAML serialiser used when PyYAML is unavailable."""
    pad = "  " * indent
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                handle.write(f"{pad}{key}:\n")
                _minimal_yaml_dump(value, handle, indent + 1)
            else:
                handle.write(f"{pad}{key}: {value}\n")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                handle.write(f"{pad}-\n")
                _minimal_yaml_dump(item, handle, indent + 1)
            else:
                handle.write(f"{pad}- {item}\n")
