"""End-to-end FTP smoke test using the stdlib ftplib client.

Starts a real FTPListener on an ephemeral port bound to 127.0.0.1 and
exercises login, PASV, LIST, STOR (upload), RETR (download), SIZE and MKD
exactly as a standard FTP client would. Prints PASS/FAIL and exits nonzero
on failure. Nothing is exposed beyond loopback.
"""

from __future__ import annotations

import io
import sys
import time
from ftplib import FTP

from aegistrap.core.config import load_config
from aegistrap.core.database import Database
from aegistrap.core.logger import get_logger
from aegistrap.core.session import SessionManager
from aegistrap.core.threat_engine import ThreatEngine
from aegistrap.listeners.ftp_listener import FTPListener

TEST_PORT = 2399
failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}{(' -> ' + detail) if detail else ''}")
    if not cond:
        failures.append(name)


def main() -> int:
    cfg = load_config()
    cfg.ftp.listen_host = "127.0.0.1"
    cfg.ftp.listen_port = TEST_PORT
    cfg.dashboard.enabled = False

    logger = get_logger(name="ftp-smoke", log_dir="logs", console=False)
    db = Database(path="data/_ftp_smoke.db", pool_size=2, enable_wal=True)
    sessions = SessionManager(database=db, logger=logger)
    threats = ThreatEngine(config=cfg.threat, database=db, logger=logger)

    listener = FTPListener(
        config=cfg, database=db, session_manager=sessions,
        threat_engine=threats, logger=logger,
    )
    listener.start()
    time.sleep(0.6)

    try:
        ftp = FTP()
        ftp.connect("127.0.0.1", TEST_PORT, timeout=10)
        welcome = ftp.getwelcome()
        check("220 banner", welcome.startswith("220"), welcome)

        login_resp = ftp.login("attacker", "hunter2")
        check("230 login accepted", login_resp.startswith("230"), login_resp)

        check("PWD is /", ftp.pwd() == "/", ftp.pwd())

        # Directory listing (PASV + LIST) over the seeded virtual FS.
        entries: list[str] = []
        ftp.retrlines("LIST", entries.append)
        check("LIST returns rows", len(entries) > 0, f"{len(entries)} rows")
        check("LIST shows /etc", any("etc" in e for e in entries))

        # Change directory into a seeded path.
        ftp.cwd("/etc")
        check("CWD /etc", ftp.pwd() == "/etc", ftp.pwd())
        ftp.cwd("/")

        # Upload a file (STOR) and verify it is captured.
        payload = b"malicious-payload-\x00-1234\nsecond line\n"
        ftp.storbinary("STOR loot.bin", io.BytesIO(payload))
        size = ftp.size("/loot.bin")
        check("SIZE after STOR", size is not None and size > 0, str(size))

        # Download it back (RETR).
        buf = io.BytesIO()
        ftp.retrbinary("RETR /loot.bin", buf.write)
        check("RETR returns data", len(buf.getvalue()) > 0, f"{len(buf.getvalue())} bytes")

        # Make a directory (MKD).
        mkd = ftp.mkd("/tmp/dropzone")
        check("MKD /tmp/dropzone", "dropzone" in mkd, mkd)
        ftp.cwd("/tmp/dropzone")
        check("CWD into new dir", ftp.pwd() == "/tmp/dropzone", ftp.pwd())

        ftp.quit()

        # Verify capture in the database.
        time.sleep(0.3)
        files = db.fetchall("SELECT action, filename, size, status FROM files")
        creds = db.fetchall("SELECT username, password, success FROM credentials WHERE protocol='ftp'")
        check("upload recorded", any(f["action"] == "upload" for f in files), str(files))
        check("download recorded", any(f["action"] == "download" for f in files))
        check("credential captured", any(c["username"] == "attacker" for c in creds), str(creds))
    finally:
        listener.stop()
        db.close()

    print("-" * 50)
    if failures:
        print(f"RESULT: {len(failures)} FAILURE(S): {failures}")
        return 1
    print("RESULT: ALL FTP CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
