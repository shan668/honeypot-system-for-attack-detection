"""SSH protocol emulator backed by Paramiko."""

from __future__ import annotations

import posixpath
import shlex
import socket
import threading
import time
from pathlib import Path
from typing import Any

from aegistrap.core.command_engine import CommandEngine
from aegistrap.core.virtual_fs import VNode, VirtualSessionState
from aegistrap.utils.probe_analysis import decode_network_text

try:
    import paramiko
except ImportError:  # pragma: no cover - fallback for minimal installs
    paramiko = None  # type: ignore[assignment]


class SSHEmulator:
    """A real SSH-protocol honeypot with a fake shell."""

    def __init__(self, config: Any, database: Any, session_manager: Any, threat_engine: Any, logger: Any) -> None:
        self.config = config
        self.db = database
        self.sessions = session_manager
        self.threats = threat_engine
        self.logger = logger
        self._host_key = self._load_host_key() if paramiko is not None else None
        self.commands = CommandEngine()

    def handle_connection(self, sock: socket.socket, addr: tuple[str, int], service_config: Any) -> None:
        if paramiko is None or self._host_key is None:
            self._handle_text_fallback(sock, addr, service_config)
            return

        source_ip, source_port = addr
        session = self.sessions.start_session(
            "ssh", source_ip, source_port, service_config.listen_port
        )
        server = _SSHServer(self, session)
        # One virtual Linux session shared by the interactive shell, exec
        # requests, SCP transfers, and the SFTP subsystem so filesystem
        # changes are consistent within a connection.
        state = VirtualSessionState(hostname=self.config.fake_hostname)
        transport = None
        try:
            sock.settimeout(15)
            transport = paramiko.Transport(sock)
            transport.local_version = service_config.banner
            transport.add_server_key(self._host_key)
            transport.set_subsystem_handler(
                "sftp", paramiko.SFTPServer, _SFTPServer, self, session, state
            )
            transport.start_server(server=server)
            channel = transport.accept(30)
            if channel is None:
                self.sessions.close_session(session.id, outcome="no_channel")
                return
            server.channel = channel
            server.ready.wait(10)
            state.username = server.username or "root"
            state.env["USER"] = state.username
            state.env["HOME"] = "/root" if state.username == "root" else f"/home/{state.username}"
            if server.exec_command:
                if _is_scp_command(server.exec_command):
                    self._handle_scp(channel, session, state, server.exec_command)
                else:
                    self._handle_exec(channel, session, state, server.exec_command)
            else:
                self._handle_shell(channel, session, state)
            # Keep the transport alive so subsequent channels on the same
            # connection (SFTP subsystem in particular, but also additional
            # exec/shell requests) are dispatched by paramiko instead of
            # hitting EOF when the client multiplexes.  We wait up to
            # ``ssh_post_channel_idle_s`` seconds, exiting early if the client
            # disconnects.
            idle_deadline = time.time() + float(
                getattr(service_config, "post_channel_idle_s", 30)
            )
            while transport.is_active() and time.time() < idle_deadline:
                time.sleep(0.5)
            self.sessions.close_session(session.id, outcome="completed")
        except (OSError, EOFError, TimeoutError):
            self.sessions.close_session(session.id, outcome="disconnected")
        except Exception as exc:
            self.logger.error("SSH emulator error", error=str(exc), source_ip=source_ip)
            self.sessions.close_session(session.id, outcome="error", notes=str(exc))
        finally:
            try:
                if transport is not None:
                    transport.close()
            except Exception:
                pass

    def record_password_attempt(self, session: Any, username: str, password: str) -> None:
        self.db.record_credential(
            {
                "session_id": session.id,
                "protocol": "ssh",
                "username": username,
                "password": password,
                "success": 0,
                "attempt_number": session.metadata.get("attempt_number", 1),
                "timestamp": time.time(),
                "source_ip": session.source_ip,
            }
        )
        session.credentials.append({"username": username, "password": password, "success": False})
        self.threats.record_login_attempt(session.source_ip, "ssh", username, False, session.id)

    def record_publickey_attempt(self, session: Any, username: str, key: Any) -> None:
        """Record a public-key authentication attempt (type + fingerprint)."""
        try:
            key_type = key.get_name()
            fingerprint = _key_fingerprint(key)
            bits = getattr(key, "get_bits", lambda: 0)()
        except Exception:  # pragma: no cover - defensive
            key_type, fingerprint, bits = "unknown", "", 0
        self.record_ssh_event(
            session,
            "publickey_attempt",
            {
                "username": username,
                "key_type": key_type,
                "fingerprint": fingerprint,
                "bits": bits,
            },
        )
        self.threats.record_login_attempt(session.source_ip, "ssh", username, False, session.id)

    def record_ssh_event(self, session: Any, event_type: str, details: dict[str, Any]) -> None:
        """Persist a structured SSH protocol event (resize, sftp, scp, ...)."""
        try:
            self.db.record_ssh_event(
                {
                    "session_id": session.id,
                    "event_type": event_type,
                    "details": details,
                    "timestamp": time.time(),
                    "source_ip": session.source_ip,
                }
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.error("Failed to record SSH event", error=str(exc))

    def record_file_transfer(
        self, session: Any, action: str, filename: str, size: int, status: str = "completed"
    ) -> None:
        """Record an SFTP/SCP file transfer in the files table."""
        try:
            self.db.record_file(
                {
                    "session_id": session.id,
                    "action": action,
                    "filename": filename,
                    "size": size,
                    "mime_type": "application/octet-stream",
                    "status": status,
                    "timestamp": time.time(),
                    "source_ip": session.source_ip,
                }
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.error("Failed to record file transfer", error=str(exc))

    def record_command(self, session: Any, state: VirtualSessionState, command: str) -> tuple[str, int, bool]:
        result = self.commands.run(state, command)
        self.db.record_command(
            {
                "session_id": session.id,
                "protocol": "ssh",
                "command": command,
                "output": result.output,
                "is_valid": 1,
                "exit_code": result.exit_code,
                "timestamp": time.time(),
                "source_ip": session.source_ip,
            }
        )
        session.commands.append({"command": command, "timestamp": time.time()})
        self.threats.record_command(session.source_ip, "ssh", command, session.id)
        return result.output, result.exit_code, result.close_session

    def _handle_shell(self, channel: Any, session: Any, state: VirtualSessionState) -> None:
        prompt = self._prompt(state)
        channel.send("Welcome to Ubuntu 22.04.4 LTS\r\n")
        channel.send("Last login: Mon Jul  6 21:43:12 2026 from 192.168.1.2\r\n")
        channel.send(prompt)
        line = bytearray()
        while True:
            data = channel.recv(1024)
            if not data:
                return
            for byte in data:
                if byte in (10, 13):
                    command = decode_network_text(bytes(line)).strip()
                    line.clear()
                    if not command:
                        channel.send("\r\n" + prompt)
                        continue
                    output, _exit_code, close_session = self.record_command(session, state, command)
                    channel.send("\r\n")
                    if output:
                        channel.send(output.replace("\n", "\r\n") + "\r\n")
                    if close_session:
                        return
                    channel.send(self._prompt(state))
                elif byte in (3, 4):
                    return
                elif byte in (8, 127):
                    if line:
                        line.pop()
                        channel.send("\b \b")
                else:
                    line.append(byte)
                    channel.send(bytes([byte]))

    def _handle_exec(self, channel: Any, session: Any, state: VirtualSessionState, command: str) -> None:
        output, exit_code, _close_session = self.record_command(session, state, command)
        if output:
            channel.send(output + "\n")
        channel.send_exit_status(exit_code)
        channel.close()

    def _handle_scp(self, channel: Any, session: Any, state: VirtualSessionState, command: str) -> None:
        """Speak the SCP protocol over an exec channel (``scp -t`` / ``scp -f``).

        This lets the OpenSSH ``scp`` client upload and download files against
        the virtual filesystem without protocol errors. Only the classic SCP
        wire protocol is implemented (sufficient for the stock client); nothing
        is executed on the host.
        """
        try:
            args = shlex.split(command)
        except ValueError:
            channel.send_exit_status(1)
            channel.close()
            return
        self.record_ssh_event(session, "scp", {"command": command})
        self.db.record_command(
            {
                "session_id": session.id,
                "protocol": "ssh",
                "command": command,
                "output": "",
                "is_valid": 1,
                "exit_code": 0,
                "timestamp": time.time(),
                "source_ip": session.source_ip,
            }
        )
        sink = "-t" in args        # server receives (client uploads)
        source = "-f" in args      # server sends (client downloads)
        target = args[-1] if args else "."
        try:
            if sink:
                self._scp_receive(channel, session, state, target)
            elif source:
                self._scp_send(channel, session, state, target)
            else:
                channel.sendall(b"\x01scp: unsupported mode\n")
        except (OSError, EOFError):
            pass
        finally:
            try:
                channel.send_exit_status(0)
            except Exception:  # pragma: no cover
                pass
            channel.close()

    def _scp_receive(self, channel: Any, session: Any, state: VirtualSessionState, target: str) -> None:
        """Handle ``scp -t`` (client is uploading one or more files to us)."""
        max_bytes = int(getattr(self.config, "ftp_max_upload_bytes", 10 * 1024 * 1024))
        channel.sendall(b"\x00")  # ready
        buf = bytearray()
        while True:
            header = self._scp_read_line(channel, buf)
            if header is None or header == "":
                return
            code = header[0]
            if code == "C":  # file: "Cmmmm <size> <name>"
                try:
                    _mode, size_str, name = header[1:].split(" ", 2)
                    size = int(size_str)
                except ValueError:
                    channel.sendall(b"\x02bad C directive\n")
                    return
                channel.sendall(b"\x00")
                data = self._scp_read_n(channel, buf, size)
                # consume trailing status byte from client
                self._scp_read_n(channel, buf, 1)
                dest = state.resolve(name if target in (".", "") else posixpath.join(target, name)
                                     if state.is_dir(target) else target)
                truncated = len(data) >= max_bytes
                state.write_file(dest, data[:max_bytes].decode("utf-8", "replace"))
                self.record_file_transfer(
                    session, "upload", dest, len(data),
                    status="truncated" if truncated else "completed",
                )
                self.threats.record_command(session.source_ip, "ssh", f"scp upload {dest}", session.id)
                channel.sendall(b"\x00")
            elif code == "D":  # entering directory — accept, no-op
                channel.sendall(b"\x00")
            elif code == "E":  # leaving directory
                channel.sendall(b"\x00")
            elif code == "T":  # timestamp directive
                channel.sendall(b"\x00")
            else:
                channel.sendall(b"\x00")

    def _scp_send(self, channel: Any, session: Any, state: VirtualSessionState, target: str) -> None:
        """Handle ``scp -f`` (client is downloading a file from us)."""
        path = state.resolve(target)
        try:
            content = state.read_file(path)
        except FileNotFoundError:
            channel.sendall(b"\x01scp: " + target.encode() + b": No such file or directory\n")
            return
        except IsADirectoryError:
            channel.sendall(b"\x01scp: " + target.encode() + b": not a regular file\n")
            return
        raw = content.encode("utf-8", "replace")
        # Wait for the client's initial readiness byte.
        self._scp_read_n(channel, bytearray(), 1)
        name = posixpath.basename(path) or "download"
        channel.sendall(f"C0644 {len(raw)} {name}\n".encode())
        self._scp_read_n(channel, bytearray(), 1)
        channel.sendall(raw)
        channel.sendall(b"\x00")
        self._scp_read_n(channel, bytearray(), 1)
        self.record_file_transfer(session, "download", path, len(raw))

    @staticmethod
    def _scp_read_line(channel: Any, buf: bytearray) -> str | None:
        while b"\n" not in buf:
            chunk = channel.recv(4096)
            if not chunk:
                if buf:
                    break
                return None
            buf.extend(chunk)
        idx = buf.find(b"\n")
        if idx == -1:
            line = bytes(buf)
            buf.clear()
        else:
            line = bytes(buf[:idx])
            del buf[: idx + 1]
        return decode_network_text(line)

    @staticmethod
    def _scp_read_n(channel: Any, buf: bytearray, count: int) -> bytes:
        while len(buf) < count:
            chunk = channel.recv(min(65536, count - len(buf)))
            if not chunk:
                break
            buf.extend(chunk)
        data = bytes(buf[:count])
        del buf[:count]
        return data

    def _load_host_key(self) -> Any:
        key_path = Path("data") / "ssh_host_rsa.key"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            return paramiko.RSAKey.from_private_key_file(str(key_path))
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(key_path))
        return key

    # ------------------------------------------------------------------ #
    # Plain TCP fallback used only when Paramiko is unavailable.
    # ------------------------------------------------------------------ #
    def _handle_text_fallback(self, sock: socket.socket, addr: tuple[str, int], service_config: Any) -> None:
        source_ip, source_port = addr
        session = self.sessions.start_session(
            "ssh", source_ip, source_port, service_config.listen_port
        )
        sock.settimeout(60)
        try:
            self._send(sock, service_config.banner + "\r\n")
            username = self._ask(sock, "login as: ")
            password = self._ask(sock, f"{username or 'user'}@{self.config.fake_hostname}'s password: ")
            self.record_password_attempt(session, username, password)
            state = VirtualSessionState(username=username or "root", hostname=self.config.fake_hostname)
            session.metadata["virtual_state"] = state
            self._send(sock, "Permission denied, please try again.\r\n")
            self._send(sock, self._prompt(state))
            while True:
                command = self._readline(sock)
                if command is None:
                    break
                command = command.strip()
                if not command:
                    self._send(sock, self._prompt(state))
                    continue
                output, _exit_code, close_session = self.record_command(session, state, command)
                if close_session:
                    self._send(sock, "logout\r\n")
                    break
                self._send(sock, output + f"\r\n{self._prompt(state)}")
            self.sessions.close_session(session.id, outcome="completed")
        except (OSError, TimeoutError):
            self.sessions.close_session(session.id, outcome="disconnected")
        except Exception as exc:
            self.logger.error("SSH fallback error", error=str(exc), source_ip=source_ip)
            self.sessions.close_session(session.id, outcome="error", notes=str(exc))

    def _ask(self, sock: socket.socket, prompt: str) -> str:
        self._send(sock, prompt)
        return (self._readline(sock) or "").strip()

    def _readline(self, sock: socket.socket) -> str | None:
        data = bytearray()
        while len(data) < 4096:
            chunk = sock.recv(1)
            if not chunk:
                return None if not data else decode_network_text(bytes(data))
            if chunk in (b"\n", b"\r"):
                return decode_network_text(bytes(data))
            data.extend(chunk)
        return decode_network_text(bytes(data))

    def _send(self, sock: socket.socket, text: str) -> None:
        sock.sendall(text.encode("utf-8", "replace"))

    def _prompt(self, state: VirtualSessionState) -> str:
        cwd = "~" if state.cwd == state.env.get("HOME") else state.cwd
        return f"{state.username}@{state.hostname}:{cwd}$ "


class _SSHServer(paramiko.ServerInterface if paramiko is not None else object):
    """Paramiko server interface: captures auth and channel requests."""

    def __init__(self, emulator: SSHEmulator, session: Any) -> None:
        self.emulator = emulator
        self.session = session
        self.ready = threading.Event()
        self.username = ""
        self.exec_command = ""
        self.channel = None
        # Terminal geometry, updated by PTY and window-change requests so the
        # emulated shell can report a believable size.
        self.term = "xterm-256color"
        self.width = 80
        self.height = 24

    def get_allowed_auths(self, username: str) -> str:
        # Offer both so clients present public keys (captured) before falling
        # back to the password prompt.
        return "publickey,password"

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        self.emulator.record_password_attempt(self.session, username, password)
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: Any) -> int:
        # Record the offered key (type + fingerprint) for intelligence, then
        # fail the method so the client falls back to password auth. This is
        # both realistic (most servers reject unknown keys) and higher-signal.
        self.username = username
        self.emulator.record_publickey_attempt(self.session, username, key)
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(
        self,
        channel: Any,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        self.term = decode_network_text(term) or "xterm-256color"
        self.width = width or 80
        self.height = height or 24
        return True

    def check_channel_window_change_request(
        self,
        channel: Any,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
    ) -> bool:
        # Honour interactive terminal resizes (e.g. an attacker resizing their
        # window mid-session). Recorded so shell output stays consistent.
        self.width = width or self.width
        self.height = height or self.height
        self.emulator.record_ssh_event(
            self.session,
            "window_change",
            {"width": self.width, "height": self.height},
        )
        return True

    def check_channel_shell_request(self, channel: Any) -> bool:
        self.ready.set()
        return True

    def check_channel_exec_request(self, channel: Any, command: bytes) -> bool:
        self.exec_command = decode_network_text(command).strip()
        self.ready.set()
        return True

    def check_channel_subsystem_request(self, channel: Any, name: str) -> bool:
        # SFTP is handled by paramiko's SubsystemHandler, registered on the
        # transport in SSHEmulator.handle_connection.
        return super().check_channel_subsystem_request(channel, name)


# --------------------------------------------------------------------------- #
# Module-level helpers
# --------------------------------------------------------------------------- #
def _is_scp_command(command: str) -> bool:
    """True if an exec request is an ``scp`` file-transfer invocation."""
    stripped = command.strip()
    return stripped.startswith("scp ") and ("-t" in stripped.split() or "-f" in stripped.split())


def _key_fingerprint(key: Any) -> str:
    """Return an OpenSSH-style SHA256 fingerprint for a public key."""
    import base64
    import hashlib

    try:
        digest = hashlib.sha256(key.asbytes()).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    except Exception:  # pragma: no cover - defensive
        return ""


if paramiko is not None:

    class _SFTPServer(paramiko.SFTPServerInterface):
        """SFTP subsystem mapped onto a per-session virtual filesystem.

        Registered via ``transport.set_subsystem_handler`` so real ``sftp``
        clients can list, upload, download, rename and delete files. Every
        operation targets :class:`VirtualSessionState`; nothing touches the
        host filesystem.
        """

        def __init__(self, server: Any, *largs: Any, **kwargs: Any) -> None:
            # NB: do not forward *largs to the base class — paramiko's
            # SFTPServerInterface passes them on to object.__init__, which
            # rejects extra arguments. We consume them here instead.
            super().__init__(server)
            # Extra positional args come from set_subsystem_handler(...):
            # (emulator, session, state)
            self.emulator: SSHEmulator = largs[0]
            self.session = largs[1]
            self.state: VirtualSessionState = largs[2]
            self.max_bytes = int(getattr(self.emulator.config, "ftp_max_upload_bytes", 10 * 1024 * 1024))

        # -- helpers ---------------------------------------------------- #
        def _attr(self, node: VNode) -> "paramiko.SFTPAttributes":
            attr = paramiko.SFTPAttributes()
            attr.filename = posixpath.basename(node.path) or "/"
            attr.st_size = node.size
            attr.st_uid = 0
            attr.st_gid = 0
            attr.st_mtime = int(node.modified_at)
            attr.st_atime = int(node.modified_at)
            attr.st_mode = _mode_bits(node)
            return attr

        # -- directory ops --------------------------------------------- #
        def list_folder(self, path: str) -> Any:
            resolved = self.state.resolve(path)
            try:
                nodes = self.state.list_dir(resolved)
            except (FileNotFoundError, IsADirectoryError):
                return paramiko.SFTP_NO_SUCH_FILE
            self.emulator.record_ssh_event(self.session, "sftp", {"op": "list", "path": resolved})
            return [self._attr(n) for n in nodes]

        def stat(self, path: str) -> Any:
            resolved = self.state.resolve(path)
            node = self.state.nodes.get(resolved)
            if node is None:
                return paramiko.SFTP_NO_SUCH_FILE
            return self._attr(node)

        def lstat(self, path: str) -> Any:
            return self.stat(path)

        def mkdir(self, path: str, attr: Any) -> int:
            resolved = self.state.resolve(path)
            try:
                self.state.mkdir(resolved)
            except FileExistsError:
                return paramiko.SFTP_FAILURE
            except FileNotFoundError:
                return paramiko.SFTP_NO_SUCH_FILE
            self.emulator.record_ssh_event(self.session, "sftp", {"op": "mkdir", "path": resolved})
            return paramiko.SFTP_OK

        def rmdir(self, path: str) -> int:
            resolved = self.state.resolve(path)
            try:
                self.state.remove(resolved, recursive=True)
            except FileNotFoundError:
                return paramiko.SFTP_NO_SUCH_FILE
            return paramiko.SFTP_OK

        def remove(self, path: str) -> int:
            resolved = self.state.resolve(path)
            try:
                self.state.remove(resolved)
            except (FileNotFoundError, IsADirectoryError):
                return paramiko.SFTP_NO_SUCH_FILE
            self.emulator.record_ssh_event(self.session, "sftp", {"op": "remove", "path": resolved})
            return paramiko.SFTP_OK

        def rename(self, oldpath: str, newpath: str) -> int:
            src = self.state.resolve(oldpath)
            dst = self.state.resolve(newpath)
            node = self.state.nodes.get(src)
            if node is None:
                return paramiko.SFTP_NO_SUCH_FILE
            if node.node_type == "dir":
                return paramiko.SFTP_OP_UNSUPPORTED
            try:
                content = self.state.read_file(src)
                self.state.write_file(dst, content)
                self.state.remove(src)
            except (FileNotFoundError, IsADirectoryError):
                return paramiko.SFTP_FAILURE
            return paramiko.SFTP_OK

        def canonicalize(self, path: str) -> str:
            return self.state.resolve(path)

        # -- file ops --------------------------------------------------- #
        def open(self, path: str, flags: int, attr: Any) -> Any:
            import os

            resolved = self.state.resolve(path)
            writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT))
            if not writing:
                node = self.state.nodes.get(resolved)
                if node is None:
                    return paramiko.SFTP_NO_SUCH_FILE
                if node.node_type == "dir":
                    return paramiko.SFTP_FAILURE
                self.emulator.record_ssh_event(self.session, "sftp", {"op": "get", "path": resolved})
            handle = _SFTPHandle(flags)
            handle.emulator = self.emulator
            handle.session = self.session
            handle.state = self.state
            handle.path = resolved
            handle.writing = writing
            handle.max_bytes = self.max_bytes
            if writing:
                # Ensure the parent exists; create/truncate the file.
                parent = posixpath.dirname(resolved) or "/"
                if not self.state.is_dir(parent):
                    return paramiko.SFTP_NO_SUCH_FILE
                self.state.write_file(resolved, "")
            else:
                handle.read_buffer = self.state.read_file(resolved).encode("utf-8", "replace")
            return handle


    class _SFTPHandle(paramiko.SFTPHandle):
        """Handle for a single open SFTP file, backed by the virtual FS."""

        emulator: Any
        session: Any
        state: Any
        path: str = ""
        writing: bool = False
        max_bytes: int = 10 * 1024 * 1024
        read_buffer: bytes = b""

        def __init__(self, flags: int = 0) -> None:
            super().__init__(flags)
            self._write_buffer = bytearray()
            self._truncated = False
            self._max_read = 0

        def read(self, offset: int, length: int) -> Any:
            if offset >= len(self.read_buffer):
                return b""
            self._max_read = max(self._max_read, min(offset + length, len(self.read_buffer)))
            return self.read_buffer[offset: offset + length]

        def write(self, offset: int, data: bytes) -> int:
            if len(self._write_buffer) + len(data) > self.max_bytes:
                allowed = max(0, self.max_bytes - len(self._write_buffer))
                self._write_buffer.extend(data[:allowed])
                self._truncated = True
            else:
                self._write_buffer.extend(data)
            return paramiko.SFTP_OK

        def close(self) -> None:
            if self.writing:
                try:
                    self.state.write_file(
                        self.path, bytes(self._write_buffer).decode("utf-8", "replace")
                    )
                except (FileNotFoundError, IsADirectoryError):
                    pass
                self.emulator.record_file_transfer(
                    self.session, "upload", self.path, len(self._write_buffer),
                    status="truncated" if self._truncated else "completed",
                )
                self.emulator.threats.record_command(
                    self.session.source_ip, "ssh", f"sftp upload {self.path}", self.session.id
                )
            elif self._max_read > 0:
                # Client read at least part of the file: record a download.
                self.emulator.record_file_transfer(
                    self.session, "download", self.path, self._max_read
                )
            super().close()


def _mode_bits(node: "VNode") -> int:
    """Convert a VNode into POSIX st_mode bits for SFTP attributes."""
    import stat as _stat

    if node.node_type == "dir":
        return _stat.S_IFDIR | 0o755
    if node.mode.startswith("-rwx") or "x" in node.mode:
        return _stat.S_IFREG | 0o755
    return _stat.S_IFREG | 0o644
