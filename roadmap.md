# Architecture

```text
Client / Scanner
  -> Listener layer
  -> Protocol emulator
  -> Session manager
  -> Database + structured logs
  -> Threat engine
  -> Analytics + dashboard
```

## Core Modules

`aegistrap.core.config`
: Loads YAML configuration and environment overrides.

`aegistrap.core.database`
: SQLite schema and query helpers for sessions, credentials, commands,
HTTP requests, FTP/SSH events, alerts, files, services, and statistics.

`aegistrap.core.session`
: Tracks active sessions and closes stale sessions.

`aegistrap.core.virtual_fs`
: In-memory virtual Linux filesystem. Each attacker session gets isolated
files, directories, cwd, environment variables, and history.

`aegistrap.core.command_engine`
: Safe Linux command emulator. It supports common commands without ever
calling the host shell.

`aegistrap.core.threat_engine`
: Sliding-window detection for brute force, spraying, high request rate,
directory brute force, suspicious patterns, and command bursts.

## Listener Layer

`aegistrap.listeners.base`
: Generic threaded TCP listener for SSH/FTP.

`aegistrap.listeners.http_listener`
: Threaded HTTP/HTTPS listener. HTTPS wraps the socket with TLS using a
self-signed certificate generated under `config/certs/`.

## Protocol Emulators

`aegistrap.protocols.ssh`
: Paramiko-backed SSH server. Supports version negotiation, key exchange,
password authentication, PTY, shell requests, and exec requests.

`aegistrap.protocols.ftp`
: FTP command emulator. Captures USER/PASS and common FTP commands.

`aegistrap.protocols.http`
: HTTP/HTTPS app surface with gateway/admin, WordPress, phpMyAdmin, and
server-status bait pages.

## Dashboard

`aegistrap.dashboard.app`
: Flask app and JSON API.

The dashboard is intentionally local-only by default.

## Sequence: SSH Login

```text
OpenSSH client
  -> TCP 2222
  -> Paramiko transport performs SSH handshake
  -> Password submitted
  -> credential stored
  -> fake shell opens
  -> command engine runs commands in virtual session
  -> commands stored
  -> dashboard updates
```

## Sequence: HTTP Login

```text
Browser
  -> HTTP/HTTPS listener
  -> fake login page
  -> POST username/password
  -> HTTP request stored
  -> credential stored
  -> suspicious pattern alert candidate
```
