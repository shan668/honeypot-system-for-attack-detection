"""FTP protocol emulator.

This module implements a research-grade FTP honeypot that behaves like a
real ``vsftpd``-style server so that standard clients (FileZilla, ``ftp``,
``lftp``, ``curl``, ``wget``) can authenticate, browse directories, and
transfer files without protocol errors.

Every FTP session is backed by an isolated in-memory
:class:`~aegistrap.core.virtual_fs.VirtualSessionState`. Uploaded content
is captured into that virtual filesystem (never the host) up to a
configurable size limit, and both uploads and downloads are recorded in
the database via :meth:`Database.record_file`.

Security model
--------------
* Attacker input is only ever interpreted, never executed.
* Data connections are honeypot-owned sockets; passive mode binds an
  ephemeral local port and active mode connects back to the client. No
  attacker-supplied path escapes the virtual filesystem.
* Uploads are bounded by ``config.ftp_max_upload_bytes``.
"""

from __future__ import annotations

import posixpath
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from aegistrap.core.virtual_fs import VNode, VirtualSessionState
from aegistrap.utils.network import get_local_ip
from aegistrap.utils.probe_analysis import decode_network_text


@dataclass
class _DataChannel:
    """Pending FTP data-channel state for one control connection.

    Exactly one of :attr:`passive_socket` (PASV) or :attr:`active_addr`
    (PORT) is populated at a time.
    """

    passive_socket: Optional[socket.socket] = None
    active_addr: Optional[tuple[str, int]] = None
    transfer_type: str = "I"  # "A" (ASCII) or "I" (binary/image)

    def reset(self) -> None:
        """Tear down any pending passive listener and clear state."""
        if self.passive_socket is not None:
            try:
                self.passive_socket.close()
            except OSError:
                pass
        self.passive_socket = None
        self.active_addr = None


class FTPEmulator:
    """A high-interaction FTP honeypot backed by a virtual filesystem."""

    def __init__(
        self,
        config: Any,
        database: Any,
        session_manager: Any,
        threat_engine: Any,
        logger: Any,
    ) -> None:
        self.config = config
        self.db = database
        self.sessions = session_manager
        self.threats = threat_engine
        self.logger = logger

    # ------------------------------------------------------------------ #
    # Connection entry point (invoked by the ServiceListener worker)
    # ------------------------------------------------------------------ #
    def handle_connection(
        self, sock: socket.socket, addr: tuple[str, int], service_config: Any
    ) -> None:
        """Drive one FTP control connection to completion."""
        source_ip, source_port = addr
        session = self.sessions.start_session(
            "ftp", source_ip, source_port, service_config.listen_port
        )
        state = VirtualSessionState(
            username="anonymous", hostname=self.config.fake_hostname
        )
        state.cwd = "/"
        data = _DataChannel()
        ctx = _FTPContext(
            session=session,
            state=state,
            data=data,
            source_ip=source_ip,
            authenticated=False,
            pending_user="",
            rename_from="",
        )
        sock.settimeout(120)
        try:
            self._send(sock, f"220 {service_config.banner} ready\r\n")
            self.threats.record_banner_grab(source_ip, session.id)
            while True:
                line = self._readline(sock)
                if line is None:
                    break
                line = line.strip()
                if not line:
                    continue
                command, _, argument = line.partition(" ")
                command = command.upper()
                self._log_command(ctx, command, argument, line)
                should_continue = self._dispatch(sock, ctx, command, argument)
                if not should_continue:
                    break
            self.sessions.close_session(session.id, outcome="completed")
        except (OSError, TimeoutError):
            self.sessions.close_session(session.id, outcome="disconnected")
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.error("FTP emulator error", error=str(exc), source_ip=source_ip)
            self.sessions.close_session(session.id, outcome="error", notes=str(exc))
        finally:
            data.reset()

    # ------------------------------------------------------------------ #
    # Command dispatch
    # ------------------------------------------------------------------ #
    def _dispatch(
        self, sock: socket.socket, ctx: "_FTPContext", command: str, argument: str
    ) -> bool:
        """Handle a single FTP command. Returns False to close the session."""
        handler = self._COMMANDS.get(command)
        if handler is None:
            self._send(sock, "502 Command not implemented.\r\n")
            return True
        return handler(self, sock, ctx, argument)

    # -- Authentication ------------------------------------------------- #
    def _cmd_user(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        ctx.pending_user = argument or "anonymous"
        self._send(sock, "331 Please specify the password.\r\n")
        return True

    def _cmd_pass(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        username = ctx.pending_user or "anonymous"
        accept = bool(getattr(self.config, "ftp_accept_login", True))
        self.db.record_credential(
            {
                "session_id": ctx.session.id,
                "protocol": "ftp",
                "username": username,
                "password": argument,
                "success": 1 if accept else 0,
                "attempt_number": ctx.session.metadata.get("attempt_number", 1),
                "timestamp": time.time(),
                "source_ip": ctx.source_ip,
            }
        )
        ctx.session.credentials.append(
            {"username": username, "password": argument, "success": accept}
        )
        self.threats.record_login_attempt(
            ctx.source_ip, "ftp", username, accept, ctx.session.id
        )
        if accept:
            ctx.authenticated = True
            ctx.state.username = username
            self._send(sock, f"230 Login successful.\r\n")
        else:
            self._send(sock, "530 Login incorrect.\r\n")
        return True

    # -- Filesystem navigation ------------------------------------------ #
    def _cmd_pwd(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        self._send(sock, f'257 "{ctx.state.cwd}" is the current directory\r\n')
        return True

    def _cmd_cwd(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        if not self._require_auth(sock, ctx):
            return True
        target = ctx.state.resolve(argument or "/")
        if ctx.state.is_dir(target):
            ctx.state.cwd = target
            self._send(sock, f'250 Directory successfully changed.\r\n')
        else:
            self._send(sock, "550 Failed to change directory.\r\n")
        return True

    def _cmd_cdup(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        return self._cmd_cwd(sock, ctx, "..")

    # -- Transfer parameters -------------------------------------------- #
    def _cmd_type(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        code = (argument or "I").strip().upper()[:1]
        ctx.data.transfer_type = "A" if code == "A" else "I"
        self._send(sock, f"200 Switching to {'ASCII' if code == 'A' else 'Binary'} mode.\r\n")
        return True

    def _cmd_mode(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        self._send(sock, "200 Mode set to S.\r\n")
        return True

    def _cmd_stru(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        self._send(sock, "200 Structure set to F.\r\n")
        return True

    # -- Data channel setup --------------------------------------------- #
    def _cmd_pasv(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        if not self._require_auth(sock, ctx):
            return True
        ctx.data.reset()
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self._control_bind_host(sock), 0))
            listener.listen(1)
            listener.settimeout(30)
        except OSError as exc:
            self._send(sock, "425 Can't open passive connection.\r\n")
            self.logger.error("FTP PASV bind failed", error=str(exc))
            return True
        ctx.data.passive_socket = listener
        advertise_ip = self._advertise_ip(sock)
        port = listener.getsockname()[1]
        octets = advertise_ip.split(".")
        if len(octets) != 4:
            octets = ["127", "0", "0", "1"]
        p_hi, p_lo = port // 256, port % 256
        self._send(
            sock,
            "227 Entering Passive Mode ("
            f"{octets[0]},{octets[1]},{octets[2]},{octets[3]},{p_hi},{p_lo}).\r\n",
        )
        return True

    def _cmd_port(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        if not self._require_auth(sock, ctx):
            return True
        parts = argument.split(",")
        if len(parts) != 6:
            self._send(sock, "501 Illegal PORT command.\r\n")
            return True
        try:
            host = ".".join(parts[:4])
            port = int(parts[4]) * 256 + int(parts[5])
        except ValueError:
            self._send(sock, "501 Illegal PORT command.\r\n")
            return True
        ctx.data.reset()
        ctx.data.active_addr = (host, port)
        self._send(sock, "200 PORT command successful. Consider using PASV.\r\n")
        return True

    # -- Directory listing ---------------------------------------------- #
    def _cmd_list(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        return self._do_listing(sock, ctx, argument, long_format=True)

    def _cmd_nlst(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        return self._do_listing(sock, ctx, argument, long_format=False)

    def _do_listing(
        self, sock: socket.socket, ctx: "_FTPContext", argument: str, long_format: bool
    ) -> bool:
        if not self._require_auth(sock, ctx):
            return True
        # Strip any option flags (e.g. "LIST -la") an attacker may send.
        path_arg = " ".join(a for a in argument.split() if not a.startswith("-")) or None
        target = ctx.state.resolve(path_arg)
        if not ctx.state.exists(target):
            self._send(sock, "550 Failed to open directory.\r\n")
            return True
        try:
            nodes = ctx.state.list_dir(target)
        except (FileNotFoundError, IsADirectoryError):
            self._send(sock, "550 Failed to open directory.\r\n")
            return True
        if long_format:
            payload = _format_ftp_listing(nodes)
        else:
            payload = "\r\n".join(posixpath.basename(n.path) for n in nodes)
            payload = payload + "\r\n" if payload else ""
        self._send(sock, "150 Here comes the directory listing.\r\n")
        data_sock = self._open_data_connection(sock, ctx)
        if data_sock is None:
            return True
        try:
            data_sock.sendall(payload.encode("utf-8", "replace"))
        finally:
            self._close_data(data_sock, ctx)
        self._send(sock, "226 Directory send OK.\r\n")
        return True

    # -- File download -------------------------------------------------- #
    def _cmd_retr(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        if not self._require_auth(sock, ctx):
            return True
        target = ctx.state.resolve(argument)
        try:
            content = ctx.state.read_file(target)
        except FileNotFoundError:
            self._send(sock, "550 Failed to open file.\r\n")
            return True
        except IsADirectoryError:
            self._send(sock, "550 Not a regular file.\r\n")
            return True
        raw = content.encode("utf-8", "replace")
        self._send(sock, "150 Opening data connection.\r\n")
        data_sock = self._open_data_connection(sock, ctx)
        if data_sock is None:
            return True
        try:
            data_sock.sendall(raw)
        finally:
            self._close_data(data_sock, ctx)
        self.db.record_file(
            {
                "session_id": ctx.session.id,
                "action": "download",
                "filename": target,
                "size": len(raw),
                "mime_type": "application/octet-stream",
                "status": "completed",
                "timestamp": time.time(),
                "source_ip": ctx.source_ip,
            }
        )
        self._send(sock, "226 Transfer complete.\r\n")
        return True

    # -- File upload ---------------------------------------------------- #
    def _cmd_stor(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        if not self._require_auth(sock, ctx):
            return True
        target = ctx.state.resolve(argument)
        parent = posixpath.dirname(target) or "/"
        if not ctx.state.is_dir(parent):
            self._send(sock, "550 No such directory.\r\n")
            return True
        self._send(sock, "150 Ok to send data.\r\n")
        data_sock = self._open_data_connection(sock, ctx)
        if data_sock is None:
            return True
        max_bytes = int(getattr(self.config, "ftp_max_upload_bytes", 10 * 1024 * 1024))
        received = bytearray()
        truncated = False
        try:
            while True:
                chunk = data_sock.recv(65536)
                if not chunk:
                    break
                if len(received) + len(chunk) > max_bytes:
                    received.extend(chunk[: max_bytes - len(received)])
                    truncated = True
                    break
                received.extend(chunk)
        finally:
            self._close_data(data_sock, ctx)
        ctx.state.write_file(target, bytes(received).decode("utf-8", "replace"))
        self.db.record_file(
            {
                "session_id": ctx.session.id,
                "action": "upload",
                "filename": target,
                "size": len(received),
                "mime_type": "application/octet-stream",
                "status": "truncated" if truncated else "completed",
                "timestamp": time.time(),
                "source_ip": ctx.source_ip,
            }
        )
        self.threats.record_command(
            ctx.source_ip, "ftp", f"STOR {target}", ctx.session.id
        )
        self._send(sock, "226 Transfer complete.\r\n")
        return True

    # -- Mutating filesystem commands ----------------------------------- #
    def _cmd_mkd(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        if not self._require_auth(sock, ctx):
            return True
        target = ctx.state.resolve(argument)
        try:
            ctx.state.mkdir(target)
        except FileExistsError:
            self._send(sock, "550 Create directory operation failed.\r\n")
            return True
        except FileNotFoundError:
            self._send(sock, "550 Create directory operation failed.\r\n")
            return True
        self._send(sock, f'257 "{target}" created.\r\n')
        return True

    def _cmd_rmd(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        if not self._require_auth(sock, ctx):
            return True
        target = ctx.state.resolve(argument)
        try:
            ctx.state.remove(target, recursive=True)
        except FileNotFoundError:
            self._send(sock, "550 Remove directory operation failed.\r\n")
            return True
        self._send(sock, "250 Remove directory operation successful.\r\n")
        return True

    def _cmd_dele(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        if not self._require_auth(sock, ctx):
            return True
        target = ctx.state.resolve(argument)
        try:
            ctx.state.remove(target)
        except (FileNotFoundError, IsADirectoryError):
            self._send(sock, "550 Delete operation failed.\r\n")
            return True
        self._send(sock, "250 Delete operation successful.\r\n")
        return True

    def _cmd_rnfr(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        if not self._require_auth(sock, ctx):
            return True
        target = ctx.state.resolve(argument)
        if not ctx.state.exists(target):
            self._send(sock, "550 RNFR command failed.\r\n")
            return True
        ctx.rename_from = target
        self._send(sock, "350 Ready for RNTO.\r\n")
        return True

    def _cmd_rnto(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        if not self._require_auth(sock, ctx):
            return True
        if not ctx.rename_from:
            self._send(sock, "503 RNFR required first.\r\n")
            return True
        source = ctx.rename_from
        dest = ctx.state.resolve(argument)
        ctx.rename_from = ""
        try:
            node = ctx.state.nodes.get(source)
            if node is None:
                raise FileNotFoundError(source)
            if node.node_type == "dir":
                self._send(sock, "550 Rename of directories not supported.\r\n")
                return True
            content = ctx.state.read_file(source)
            ctx.state.write_file(dest, content)
            ctx.state.remove(source)
        except (FileNotFoundError, IsADirectoryError):
            self._send(sock, "550 Rename failed.\r\n")
            return True
        self._send(sock, "250 Rename successful.\r\n")
        return True

    # -- Metadata ------------------------------------------------------- #
    def _cmd_size(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        target = ctx.state.resolve(argument)
        node = ctx.state.nodes.get(target)
        if node is None or node.node_type == "dir":
            self._send(sock, "550 Could not get file size.\r\n")
            return True
        self._send(sock, f"213 {node.size}\r\n")
        return True

    def _cmd_mdtm(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        target = ctx.state.resolve(argument)
        node = ctx.state.nodes.get(target)
        if node is None:
            self._send(sock, "550 Could not get modification time.\r\n")
            return True
        stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime(node.modified_at))
        self._send(sock, f"213 {stamp}\r\n")
        return True

    # -- Informational / no-op ------------------------------------------ #
    def _cmd_syst(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        self._send(sock, "215 UNIX Type: L8\r\n")
        return True

    def _cmd_feat(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        self._send(
            sock,
            "211-Features:\r\n"
            " PASV\r\n"
            " SIZE\r\n"
            " MDTM\r\n"
            " UTF8\r\n"
            " REST STREAM\r\n"
            "211 End\r\n",
        )
        return True

    def _cmd_opts(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        if argument.strip().upper().startswith("UTF8"):
            self._send(sock, "200 Always in UTF8 mode.\r\n")
        else:
            self._send(sock, "200 OK.\r\n")
        return True

    def _cmd_noop(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        self._send(sock, "200 NOOP ok.\r\n")
        return True

    def _cmd_rest(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        self._send(sock, "350 Restart position accepted.\r\n")
        return True

    def _cmd_quit(self, sock: socket.socket, ctx: "_FTPContext", argument: str) -> bool:
        self._send(sock, "221 Goodbye.\r\n")
        return False

    # ------------------------------------------------------------------ #
    # Data-connection helpers
    # ------------------------------------------------------------------ #
    def _open_data_connection(
        self, sock: socket.socket, ctx: "_FTPContext"
    ) -> Optional[socket.socket]:
        """Return an established data socket (PASV accept or PORT connect)."""
        try:
            if ctx.data.passive_socket is not None:
                conn, _ = ctx.data.passive_socket.accept()
                conn.settimeout(60)
                return conn
            if ctx.data.active_addr is not None:
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.settimeout(30)
                conn.connect(ctx.data.active_addr)
                return conn
        except OSError as exc:
            self._send(sock, "425 Can't open data connection.\r\n")
            self.logger.error("FTP data connection failed", error=str(exc))
            ctx.data.reset()
            return None
        self._send(sock, "425 Use PORT or PASV first.\r\n")
        return None

    def _close_data(self, data_sock: socket.socket, ctx: "_FTPContext") -> None:
        try:
            data_sock.close()
        except OSError:
            pass
        ctx.data.reset()

    def _advertise_ip(self, sock: socket.socket) -> str:
        """IP address to advertise to the client for PASV connections."""
        try:
            local = sock.getsockname()[0]
            if local and local not in ("0.0.0.0", "::"):
                return local
        except OSError:
            pass
        return get_local_ip()

    def _control_bind_host(self, sock: socket.socket) -> str:
        """Interface to bind the passive listener on."""
        try:
            return sock.getsockname()[0]
        except OSError:
            return "0.0.0.0"

    # ------------------------------------------------------------------ #
    # Bookkeeping & I/O
    # ------------------------------------------------------------------ #
    def _require_auth(self, sock: socket.socket, ctx: "_FTPContext") -> bool:
        if ctx.authenticated:
            return True
        self._send(sock, "530 Please login with USER and PASS.\r\n")
        return False

    def _log_command(
        self, ctx: "_FTPContext", command: str, argument: str, raw_line: str
    ) -> None:
        # Do not persist raw passwords in the generic command log.
        logged_argument = "****" if command == "PASS" else argument
        self.db.record_ftp_event(
            {
                "session_id": ctx.session.id,
                "event_type": "command",
                "command": command,
                "argument": logged_argument,
                "response_code": 0,
                "timestamp": time.time(),
                "source_ip": ctx.source_ip,
            }
        )
        self.db.record_command(
            {
                "session_id": ctx.session.id,
                "protocol": "ftp",
                "command": command if command == "PASS" else raw_line,
                "timestamp": time.time(),
                "source_ip": ctx.source_ip,
            }
        )
        self.threats.record_command(ctx.source_ip, "ftp", command, ctx.session.id)
        ctx.session.commands.append({"command": raw_line, "timestamp": time.time()})

    def _readline(self, sock: socket.socket) -> str | None:
        data = bytearray()
        while len(data) < 4096:
            chunk = sock.recv(1)
            if not chunk:
                return None if not data else decode_network_text(bytes(data))
            if chunk == b"\n":
                return decode_network_text(bytes(data))
            if chunk != b"\r":
                data.extend(chunk)
        return decode_network_text(bytes(data))

    def _send(self, sock: socket.socket, text: str) -> None:
        sock.sendall(text.encode("utf-8", "replace"))

    # Command name -> bound handler. Declared at class scope so it is built
    # once; handlers are resolved on the instance at dispatch time.
    _COMMANDS = {
        "USER": _cmd_user,
        "PASS": _cmd_pass,
        "PWD": _cmd_pwd,
        "XPWD": _cmd_pwd,
        "CWD": _cmd_cwd,
        "XCWD": _cmd_cwd,
        "CDUP": _cmd_cdup,
        "XCUP": _cmd_cdup,
        "TYPE": _cmd_type,
        "MODE": _cmd_mode,
        "STRU": _cmd_stru,
        "PASV": _cmd_pasv,
        "PORT": _cmd_port,
        "LIST": _cmd_list,
        "NLST": _cmd_nlst,
        "RETR": _cmd_retr,
        "STOR": _cmd_stor,
        "MKD": _cmd_mkd,
        "XMKD": _cmd_mkd,
        "RMD": _cmd_rmd,
        "XRMD": _cmd_rmd,
        "DELE": _cmd_dele,
        "RNFR": _cmd_rnfr,
        "RNTO": _cmd_rnto,
        "SIZE": _cmd_size,
        "MDTM": _cmd_mdtm,
        "SYST": _cmd_syst,
        "FEAT": _cmd_feat,
        "OPTS": _cmd_opts,
        "NOOP": _cmd_noop,
        "REST": _cmd_rest,
        "QUIT": _cmd_quit,
    }


@dataclass
class _FTPContext:
    """Mutable per-connection state passed to each command handler."""

    session: Any
    state: VirtualSessionState
    data: _DataChannel
    source_ip: str
    authenticated: bool = False
    pending_user: str = ""
    rename_from: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def _format_ftp_listing(nodes: "list[VNode]") -> str:
    """Render virtual nodes as an ``ls -l`` style FTP LIST payload."""
    lines = []
    for node in nodes:
        name = posixpath.basename(node.path) or node.path
        links = 2 if node.node_type == "dir" else 1
        stamp = time.strftime("%b %d %H:%M", time.localtime(node.modified_at))
        lines.append(
            f"{node.mode} {links:>3} {node.owner:<8} {node.group:<8} "
            f"{node.size:>12} {stamp} {name}"
        )
    return ("\r\n".join(lines) + "\r\n") if lines else ""
