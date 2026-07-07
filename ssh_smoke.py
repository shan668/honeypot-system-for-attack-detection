"""SCP wire-protocol smoke test (scp -t upload / scp -f download).

paramiko has no built-in scp client, so we drive the classic SCP protocol
by hand over an exec channel. All channel recvs use timeouts so a protocol
stall surfaces as a failure rather than hanging.
"""

from __future__ import annotations

import sys
import time

import paramiko

from aegistrap.core.config import load_config
from aegistrap.core.database import Database
from aegistrap.core.logger import get_logger
from aegistrap.core.session import SessionManager
from aegistrap.core.threat_engine import ThreatEngine
from aegistrap.listeners.ssh_listener import SSHListener

PORT = 2397
fails: list[str] = []


def ck(name: str, cond: bool, detail: str = "") -> None:
    print(("[PASS] " if cond else "[FAIL] ") + name + ((" -> " + detail) if detail else ""))
    if not cond:
        fails.append(name)


def recv_exact(chan, n, timeout=10.0):
    chan.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        got = chan.recv(n - len(buf))
        if not got:
            break
        buf += got
    return buf


def recv_line(chan, timeout=10.0):
    chan.settimeout(timeout)
    buf = b""
    while not buf.endswith(b"\n"):
        got = chan.recv(1)
        if not got:
            break
        buf += got
    return buf


def main() -> int:
    cfg = load_config()
    cfg.ssh.listen_host = "127.0.0.1"
    cfg.ssh.listen_port = PORT
    cfg.dashboard.enabled = False
    lg = get_logger(name="scp", log_dir="logs", console=False)
    db = Database(path="data/_scp_smoke.db", pool_size=2, enable_wal=True)
    sm = SessionManager(database=db, logger=lg)
    th = ThreatEngine(config=cfg.threat, database=db, logger=lg)
    L = SSHListener(config=cfg, database=db, session_manager=sm, threat_engine=th, logger=lg)
    L.start()
    time.sleep(0.8)
    body = b"scp-uploaded-content\n"
    try:
        # ---- SCP UPLOAD: scp -t ----
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect("127.0.0.1", PORT, username="mallory", password="pw",
                  look_for_keys=False, allow_agent=False, timeout=10)
        ch = c.get_transport().open_session()
        ch.settimeout(10)
        ch.exec_command("scp -t /tmp/scpfile.txt")
        ck("upload: server ready", recv_exact(ch, 1) == b"\x00")
        ch.sendall(("C0644 %d scpfile.txt\n" % len(body)).encode())
        ck("upload: C-directive ack", recv_exact(ch, 1) == b"\x00")
        ch.sendall(body)
        ch.sendall(b"\x00")
        ck("upload: data ack", recv_exact(ch, 1) == b"\x00")
        ch.close()
        c.close()
        time.sleep(0.3)
        up = db.fetchall("SELECT filename, size FROM files WHERE action='upload'")
        ck("upload recorded in DB", any("scpfile" in f["filename"] for f in up), str(up))

        # ---- SCP DOWNLOAD: scp -f ----
        # New connection => fresh isolated virtual FS (per-session isolation),
        # so download a *seeded* file that exists in every session.
        target = "/etc/passwd"
        c2 = paramiko.SSHClient()
        c2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c2.connect("127.0.0.1", PORT, username="mallory", password="pw",
                   look_for_keys=False, allow_agent=False, timeout=10)
        ch2 = c2.get_transport().open_session()
        ch2.settimeout(10)
        ch2.exec_command(f"scp -f {target}")
        ch2.sendall(b"\x00")  # client ready
        hdr = recv_line(ch2)
        ck("download: C header", hdr.startswith(b"C0644") and b"passwd" in hdr, hdr.decode(errors="replace").strip())
        try:
            size = int(hdr.split(b" ")[1])
        except (IndexError, ValueError):
            size = 0
        ch2.sendall(b"\x00")  # ack header
        data = recv_exact(ch2, size)
        ck("download: content non-empty", size > 0 and len(data) == size and b"root:" in data, f"{len(data)} bytes")
        trailer = recv_exact(ch2, 1)
        ck("download: trailing status", trailer == b"\x00")
        ch2.sendall(b"\x00")  # final ack
        ch2.close()
        c2.close()
        time.sleep(0.3)
        dn = db.fetchall("SELECT filename FROM files WHERE action='download'")
        ck("download recorded in DB", any("passwd" in f["filename"] for f in dn), str(dn))
        ev = db.fetchall("SELECT DISTINCT event_type FROM ssh_events WHERE event_type='scp'")
        ck("scp event recorded", len(ev) > 0, str(ev))
    finally:
        L.stop()
        db.close()
    print("-" * 50)
    print("SCP RESULT:", "ALL PASSED" if not fails else ("FAILURES " + str(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
