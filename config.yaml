"""End-to-end SSH/SFTP smoke test using paramiko as the client.

Starts a real SSHListener on loopback and drives it with a paramiko
client to verify: password auth, exec, interactive shell + window resize,
and the SFTP subsystem (put/get/listdir/mkdir/remove). Uploads/downloads
are checked in the database. Nothing is exposed beyond loopback.
"""

from __future__ import annotations

import io
import sys
import time

import paramiko

from aegistrap.core.config import load_config
from aegistrap.core.database import Database
from aegistrap.core.logger import get_logger
from aegistrap.core.session import SessionManager
from aegistrap.core.threat_engine import ThreatEngine
from aegistrap.listeners.ssh_listener import SSHListener

TEST_PORT = 2398
failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}{(' -> ' + detail) if detail else ''}")
    if not cond:
        failures.append(name)


def main() -> int:
    cfg = load_config()
    cfg.ssh.listen_host = "127.0.0.1"
    cfg.ssh.listen_port = TEST_PORT
    cfg.dashboard.enabled = False

    logger = get_logger(name="ssh-smoke", log_dir="logs", console=False)
    db = Database(path="data/_ssh_smoke.db", pool_size=2, enable_wal=True)
    sessions = SessionManager(database=db, logger=logger)
    threats = ThreatEngine(config=cfg.threat, database=db, logger=logger)

    listener = SSHListener(
        config=cfg, database=db, session_manager=sessions,
        threat_engine=threats, logger=logger,
    )
    listener.start()
    time.sleep(0.8)

    try:
        # --- exec channel ------------------------------------------------
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            "127.0.0.1", TEST_PORT, username="attacker", password="hunter2",
            look_for_keys=False, allow_agent=False, timeout=10,
        )
        check("password auth + connect", True)

        stdin, stdout, stderr = client.exec_command("uname -a")
        out = stdout.read().decode()
        check("exec uname -a", "Linux" in out, out.strip())
        client.close()

        # --- interactive shell + window resize --------------------------
        client2 = paramiko.SSHClient()
        client2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client2.connect(
            "127.0.0.1", TEST_PORT, username="root", password="toor",
            look_for_keys=False, allow_agent=False, timeout=10,
        )
        chan = client2.invoke_shell(width=80, height=24)
        time.sleep(0.4)
        _ = chan.recv(4096)  # banner + prompt
        chan.resize_pty(width=132, height=43)  # window-change request
        chan.send("whoami\n")
        time.sleep(0.4)
        shell_out = chan.recv(4096).decode(errors="replace")
        check("interactive shell whoami", "root" in shell_out, shell_out.strip().replace("\r\n", " | "))
        chan.close()
        client2.close()

        # --- SFTP subsystem --------------------------------------------
        t = paramiko.Transport(("127.0.0.1", TEST_PORT))
        t.connect(username="attacker", password="hunter2")
        sftp = paramiko.SFTPClient.from_transport(t)

        listing = sftp.listdir("/")
        check("sftp listdir /", "etc" in listing and "root" in listing, str(sorted(listing)[:6]))

        # upload
        payload = b"sftp-implant-bytes\x00\x01\x02payload\n"
        sftp.putfo(io.BytesIO(payload), "/tmp/implant.bin")
        st = sftp.stat("/tmp/implant.bin")
        check("sftp upload + stat", st.st_size == len(payload), f"size={st.st_size}")

        # download
        back = io.BytesIO()
        sftp.getfo("/tmp/implant.bin", back)
        check("sftp download roundtrip", back.getvalue() == payload, f"{len(back.getvalue())} bytes")

        # mkdir + remove
        sftp.mkdir("/tmp/sftpdir")
        check("sftp mkdir", "sftpdir" in sftp.listdir("/tmp"))
        sftp.remove("/tmp/implant.bin")
        check("sftp remove", "implant.bin" not in sftp.listdir("/tmp"))

        sftp.close()
        t.close()

        # --- database capture ------------------------------------------
        time.sleep(0.3)
        files = db.fetchall("SELECT action, filename, size FROM files")
        events = db.fetchall("SELECT event_type FROM ssh_events")
        event_types = {e["event_type"] for e in events}
        check("sftp upload recorded", any(f["action"] == "upload" for f in files), str(files))
        check("sftp download recorded", any(f["action"] == "download" for f in files))
        check("window_change event recorded", "window_change" in event_types, str(event_types))
        check("sftp event recorded", "sftp" in event_types)
    finally:
        listener.stop()
        db.close()

    print("-" * 50)
    if failures:
        print(f"RESULT: {len(failures)} FAILURE(S): {failures}")
        return 1
    print("RESULT: ALL SSH/SFTP CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
