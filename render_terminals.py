"""HTTP protocol emulator."""

from __future__ import annotations

import html
import time
from http.server import BaseHTTPRequestHandler
from typing import Any
from urllib.parse import parse_qs, urlsplit


class HTTPEmulator:
    def __init__(self, config: Any, database: Any, session_manager: Any, threat_engine: Any, logger: Any) -> None:
        self.config = config
        self.db = database
        self.sessions = session_manager
        self.threats = threat_engine
        self.logger = logger

    def build_handler(self) -> type[BaseHTTPRequestHandler]:
        emulator = self

        class HoneypotHTTPHandler(BaseHTTPRequestHandler):
            server_version = emulator.config.http.banner
            sys_version = ""

            def do_GET(self) -> None:
                self._handle()

            def do_POST(self) -> None:
                self._handle()

            def do_PUT(self) -> None:
                self._handle()

            def do_DELETE(self) -> None:
                self._handle()

            def do_HEAD(self) -> None:
                self._handle(send_body=False)

            def do_OPTIONS(self) -> None:
                self._handle()

            def do_PATCH(self) -> None:
                self._handle()

            def log_message(self, fmt: str, *args: Any) -> None:
                emulator.logger.info("HTTP request", request_log=fmt % args)

            def _handle(self, send_body: bool = True) -> None:
                source_ip, source_port = self.client_address
                parsed = urlsplit(self.path)
                body = b""
                length = int(self.headers.get("Content-Length", "0") or 0)
                if length:
                    body = self.rfile.read(min(length, 65536))
                session = emulator.sessions.start_session(
                    "http",
                    source_ip,
                    source_port,
                    emulator.config.http.listen_port,
                    user_agent=self.headers.get("User-Agent"),
                    resolve_geo=True,
                )
                status, response, content_type = emulator._response_for(
                    parsed.path, self.command, body
                )
                if parsed.path in {"/admin", "/wp-login.php", "/phpmyadmin", "/login", "/api/login"}:
                    emulator.threats.record_suspicious_pattern(source_ip, parsed.path, session.id)
                    if self.command.upper() == "POST":
                        emulator._record_login_attempt(
                            session=session,
                            source_ip=source_ip,
                            path=parsed.path,
                            body=body,
                            content_type=self.headers.get("Content-Type", ""),
                        )
                emulator.db.record_http_request(
                    {
                        "session_id": session.id,
                        "timestamp": time.time(),
                        "method": self.command,
                        "path": parsed.path,
                        "query": parsed.query,
                        "status_code": status,
                        "user_agent": self.headers.get("User-Agent"),
                        "referrer": self.headers.get("Referer"),
                        "content_type": self.headers.get("Content-Type"),
                        "content_length": length,
                        "source_ip": source_ip,
                        "body_preview": body[:2048].decode("utf-8", "replace"),
                    }
                )
                emulator.threats.record_request(
                    source_ip,
                    self.command,
                    parsed.path,
                    self.headers.get("User-Agent"),
                    status,
                    session.id,
                )
                encoded = response.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Server", emulator.config.http.banner)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(encoded) if send_body else 0))
                self.end_headers()
                if send_body:
                    self.wfile.write(encoded)
                emulator.sessions.close_session(session.id, outcome=str(status))

        return HoneypotHTTPHandler

    def _response_for(
        self, path: str, method: str = "GET", body: bytes = b""
    ) -> tuple[int, str, str]:
        """Route a request to (status, body, content_type).

        Unknown paths return 404 so directory brute-forcers (gobuster, dirb,
        ffuf) don't detect the "wildcard 200" fingerprint that gives every
        naive honeypot away.
        """
        HTML = "text/html; charset=utf-8"
        if path in {"/", "/index.html", "/dashboard", "/status"}:
            return 200, self._portal_page(), HTML
        if path in {"/admin", "/login", "/api/login"}:
            # Login GET: show form (200). POST with any creds: re-render with
            # an error message (still 200 — real login pages don't 401 on a
            # wrong password, they show an error).
            error = method.upper() == "POST"
            return 200, self._login_page(error=error), HTML
        if path == "/wp-login.php":
            return 200, self._wordpress_login(), HTML
        if path == "/phpmyadmin":
            return 200, self._phpmyadmin_login(), HTML
        if path == "/server-status":
            return 200, self._server_status(), HTML
        if path == "/robots.txt":
            return 200, "User-agent: *\nDisallow: /admin\nDisallow: /login\n", "text/plain; charset=utf-8"
        if path == "/favicon.ico":
            # No favicon on this box — 404 like a real minimal server.
            return 404, self._not_found(path), HTML
        return 404, self._not_found(path), HTML

    def _record_login_attempt(
        self,
        session: Any,
        source_ip: str,
        path: str,
        body: bytes,
        content_type: str,
    ) -> None:
        fields = self._parse_form_body(body, content_type)
        username_keys = ("username", "user", "login", "log", "pma_username", "email")
        password_keys = ("password", "pass", "pwd", "pma_password")
        username = self._first_field(fields, username_keys)
        password = self._first_field(fields, password_keys)
        if not username and not password:
            return
        self.db.record_credential(
            {
                "session_id": session.id,
                "protocol": "http",
                "username": username,
                "password": password,
                "success": 0,
                "attempt_number": session.metadata.get("attempt_number", 1),
                "timestamp": time.time(),
                "source_ip": source_ip,
            }
        )
        self.db.record_command(
            {
                "session_id": session.id,
                "protocol": "http",
                "command": f"POST {path} username={username}",
                "output": "401 Unauthorized",
                "is_valid": 1,
                "exit_code": 401,
                "timestamp": time.time(),
                "source_ip": source_ip,
            }
        )
        self.threats.record_login_attempt(source_ip, "http", username, False, session.id)

    def _parse_form_body(self, body: bytes, content_type: str) -> dict[str, list[str]]:
        if not body:
            return {}
        text = body.decode("utf-8", "replace")
        if "application/x-www-form-urlencoded" in content_type.lower() or "=" in text:
            return parse_qs(text, keep_blank_values=True)
        return {}

    def _first_field(self, fields: dict[str, list[str]], keys: tuple[str, ...]) -> str:
        lowered = {key.lower(): value for key, value in fields.items()}
        for key in keys:
            values = lowered.get(key)
            if values:
                return values[0]
        return ""

    def _page(self, title: str, body: str) -> str:
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    :root {{ --blue:#1f5f99; --dark:#1f2933; --line:#d8dee6; --muted:#66788a; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:Arial, Helvetica, sans-serif; background:#eef2f6; color:#1f2933; }}
    header {{ background:linear-gradient(#255f91,#17496f); color:white; padding:16px 28px; box-shadow:0 2px 8px rgba(0,0,0,.18); }}
    header h1 {{ margin:0; font-size:22px; font-weight:600; }}
    header small {{ opacity:.82; }}
    nav {{ background:#ffffff; border-bottom:1px solid var(--line); padding:9px 28px; }}
    nav a {{ color:#1f5f99; margin-right:22px; text-decoration:none; font-size:14px; }}
    main {{ max-width:1120px; margin:24px auto; padding:0 20px; }}
    .grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:16px; }}
    .card {{ background:white; border:1px solid var(--line); border-radius:4px; padding:18px; box-shadow:0 1px 2px rgba(0,0,0,.04); }}
    .card h2 {{ margin:0 0 12px; font-size:17px; color:#17496f; }}
    .label {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
    .value {{ font-size:20px; margin-top:4px; }}
    .ok {{ color:#218838; font-weight:bold; }}
    .warn {{ color:#b7791f; font-weight:bold; }}
    table {{ width:100%; border-collapse:collapse; background:white; border:1px solid var(--line); }}
    th,td {{ padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; font-size:14px; }}
    th {{ background:#f7f9fb; color:#4a5568; }}
    .login {{ max-width:420px; margin:44px auto; }}
    input {{ width:100%; padding:10px; border:1px solid #b8c2cc; border-radius:3px; margin:6px 0 14px; }}
    button {{ background:#1f5f99; color:white; border:0; border-radius:3px; padding:10px 18px; cursor:pointer; }}
    .error {{ background:#fff5f5; color:#b91c1c; border:1px solid #fecaca; padding:10px; margin-bottom:14px; }}
    .muted {{ color:var(--muted); }}
    @media (max-width:800px) {{ .grid {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body>
  <header><h1>Edge Gateway Management</h1><small>{html.escape(self.config.fake_hostname)} · Apache/2.4.57 · Maintenance Console</small></header>
  <nav><a href="/">Status</a><a href="/admin">Administration</a><a href="/server-status">Server Status</a><a href="/support">Support</a></nav>
  <main>{body}</main>
</body>
</html>"""

    def _portal_page(self) -> str:
        body = f"""
<section class="grid">
  <div class="card"><div class="label">System status</div><div class="value ok">Online</div><p class="muted">Last health check: just now</p></div>
  <div class="card"><div class="label">Hostname</div><div class="value">{html.escape(self.config.fake_hostname)}</div><p class="muted">LAN gateway service</p></div>
  <div class="card"><div class="label">Firmware</div><div class="value warn">8.9.3 LTS</div><p class="muted">Update channel: stable</p></div>
</section>
<section class="card" style="margin-top:18px">
  <h2>Service Overview</h2>
  <table>
    <tr><th>Service</th><th>Status</th><th>Bind</th><th>Notes</th></tr>
    <tr><td>Web management</td><td class="ok">Running</td><td>0.0.0.0:8080</td><td>Local network access enabled</td></tr>
    <tr><td>SSH maintenance</td><td class="ok">Running</td><td>0.0.0.0:2222</td><td>Key rotation pending</td></tr>
    <tr><td>FTP recovery</td><td class="warn">Limited</td><td>0.0.0.0:2121</td><td>Anonymous access disabled</td></tr>
  </table>
</section>
<section class="card" style="margin-top:18px">
  <h2>Administrative Access</h2>
  <p>Sign in to manage routing, backup, firmware, and diagnostics.</p>
  <p><a href="/admin"><button>Open Administration</button></a></p>
</section>"""
        return self._page("Edge Gateway Management", body)

    def _login_page(self, error: bool = False) -> str:
        err = '<div class="error">Invalid username or password. This attempt has been logged.</div>' if error else ""
        body = f"""
<section class="card login">
  <h2>Administrator Sign In</h2>
  {err}
  <form method="post" action="/admin">
    <label>Username</label>
    <input name="username" autocomplete="username" autofocus>
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password">
    <button type="submit">Sign In</button>
  </form>
  <p class="muted">Authorized access only. Failed attempts are recorded.</p>
</section>"""
        return self._page("Administration Login", body)

    def _wordpress_login(self) -> str:
        body = """
<section class="card login">
  <h2>WordPress Login</h2>
  <form method="post" action="/wp-login.php">
    <label>Username or Email Address</label>
    <input name="log">
    <label>Password</label>
    <input name="pwd" type="password">
    <button type="submit">Log In</button>
  </form>
  <p class="muted">Powered by WordPress</p>
</section>"""
        return self._page("Log In ‹ Intranet — WordPress", body)

    def _phpmyadmin_login(self) -> str:
        body = """
<section class="card login">
  <h2>phpMyAdmin</h2>
  <p class="muted">MySQL server: localhost</p>
  <form method="post" action="/phpmyadmin">
    <label>Username</label>
    <input name="pma_username">
    <label>Password</label>
    <input name="pma_password" type="password">
    <button type="submit">Go</button>
  </form>
</section>"""
        return self._page("phpMyAdmin", body)

    def _server_status(self) -> str:
        body = """
<section class="card">
  <h2>Apache Server Status</h2>
  <p class="error">Access denied: server-status is restricted to local administrators.</p>
  <table>
    <tr><th>Server Version</th><td>Apache/2.4.57 (Ubuntu)</td></tr>
    <tr><th>Server MPM</th><td>event</td></tr>
    <tr><th>Uptime</th><td>3 days 04:17:22</td></tr>
  </table>
</section>"""
        return self._page("Apache Status", body)

    def _not_found(self, path: str) -> str:
        body = f"""
<section class="card">
  <h2>404 Not Found</h2>
  <p>The requested URL <code>{html.escape(path)}</code> was not found on this server.</p>
  <p class="muted">Apache/2.4.57 Server at {html.escape(self.config.fake_hostname)} Port 8080</p>
</section>"""
        return self._page("404 Not Found", body)
