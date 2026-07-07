"""End-to-end smoke test for dashboard CSV/JSON export endpoints.

Uses Flask's built-in test client (no sockets) to hit /api/export/<dataset>
for each dataset in both csv and json formats. Verifies:

  - status 200 and correct Content-Type
  - Content-Disposition attachment filename
  - CSV parses cleanly and includes seeded rows
  - JSON is a list containing seeded rows
  - Filter query params are honoured (subset returned)
  - Unknown datasets return 404
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from aegistrap.core.config import load_config
from aegistrap.core.database import Database
from aegistrap.core.logger import get_logger
from aegistrap.core.session import SessionManager
from aegistrap.core.threat_engine import ThreatEngine
from aegistrap.core.analytics import AnalyticsEngine
from aegistrap.dashboard.app import create_dashboard_app


def main() -> int:
    fails: list[str] = []

    def ck(name: str, cond: bool, detail: str = "") -> None:
        mark = "[PASS]" if cond else "[FAIL]"
        line = f"{mark} {name}"
        if detail:
            line += f" -> {detail}"
        print(line)
        if not cond:
            fails.append(name)

    cfg = load_config()
    cfg.dashboard.enabled = False  # we drive it via test client, not run()
    logger = get_logger(name="export-smoke", log_dir="logs", console=False)
    db = Database(path="data/_export_smoke.db", pool_size=2, enable_wal=True)
    sm = SessionManager(database=db, logger=logger)
    te = ThreatEngine(config=cfg.threat, database=db, logger=logger)
    analytics = AnalyticsEngine(database=db)

    # ---- Seed test data ----
    now = time.time()
    db.record_credential({
        "session_id": "sess-1", "source_ip": "10.0.0.5", "protocol": "ssh",
        "username": "root", "password": "toor", "timestamp": now, "success": 0,
    })
    db.record_credential({
        "session_id": "sess-2", "source_ip": "10.0.0.6", "protocol": "ssh",
        "username": "admin", "password": "admin", "timestamp": now, "success": 0,
    })
    db.record_command({
        "session_id": "sess-1", "source_ip": "10.0.0.5", "protocol": "ssh",
        "command": "uname -a", "timestamp": now, "is_valid": 1,
    })
    db.record_http_request({
        "session_id": "sess-3", "source_ip": "10.0.0.7", "method": "GET",
        "path": "/admin", "status_code": 401, "user_agent": "curl/8",
        "timestamp": now,
    })

    # Sessions/alerts are more work to seed via the record path; we can still
    # exercise the endpoints (empty result should still 200 with valid output).
    app = create_dashboard_app(
        config=cfg, database=db, analytics=analytics,
        session_manager=sm, threat_engine=te, logger=logger, listeners={},
    )
    client = app.test_client()

    # ---- Test each dataset in both formats ----
    datasets = ["sessions", "credentials", "commands", "http", "alerts"]
    for ds in datasets:
        for fmt in ("csv", "json"):
            resp = client.get(f"/api/export/{ds}?format={fmt}")
            ck(f"{ds}:{fmt} status 200", resp.status_code == 200, str(resp.status_code))
            ctype = resp.headers.get("Content-Type", "")
            expected_ct = "text/csv" if fmt == "csv" else "application/json"
            ck(f"{ds}:{fmt} content-type", expected_ct in ctype, ctype)
            disp = resp.headers.get("Content-Disposition", "")
            ck(f"{ds}:{fmt} attachment header",
               f'aegistrap_{ds}.{fmt}' in disp, disp)
            body = resp.get_data(as_text=True)
            if fmt == "json":
                try:
                    parsed = json.loads(body or "[]")
                    ck(f"{ds}:json is list", isinstance(parsed, list),
                       type(parsed).__name__)
                except json.JSONDecodeError as exc:
                    ck(f"{ds}:json parses", False, str(exc))
            else:
                # CSV parses (empty body is ok — no seeded rows for some tables)
                if body:
                    reader = csv.reader(io.StringIO(body))
                    rows = list(reader)
                    ck(f"{ds}:csv parses", len(rows) >= 1, f"{len(rows)} rows")

    # ---- Content-level checks: seeded rows appear ----
    creds_json = json.loads(client.get("/api/export/credentials?format=json").get_data(as_text=True))
    ck("credentials json contains seeded rows",
       any(r.get("username") == "root" for r in creds_json), f"{len(creds_json)} rows")

    creds_csv = client.get("/api/export/credentials?format=csv").get_data(as_text=True)
    ck("credentials csv contains 'root'", "root" in creds_csv,
       creds_csv.splitlines()[0] if creds_csv else "")

    cmds_json = json.loads(client.get("/api/export/commands?format=json").get_data(as_text=True))
    ck("commands json has uname",
       any("uname" in (r.get("command") or "") for r in cmds_json), f"{len(cmds_json)} rows")

    http_json = json.loads(client.get("/api/export/http?format=json").get_data(as_text=True))
    ck("http json has /admin",
       any(r.get("path") == "/admin" for r in http_json), f"{len(http_json)} rows")

    # ---- Filter query params honoured ----
    filtered = json.loads(
        client.get("/api/export/credentials?format=json&username=root").get_data(as_text=True)
    )
    ck("credentials filter honoured (only root)",
       all(r.get("username") == "root" for r in filtered) and len(filtered) >= 1,
       f"{len(filtered)} rows")

    filtered_ip = json.loads(
        client.get("/api/export/credentials?format=json&ip=10.0.0.5").get_data(as_text=True)
    )
    ck("credentials filter by ip",
       all(r.get("source_ip") == "10.0.0.5" for r in filtered_ip) and len(filtered_ip) >= 1,
       f"{len(filtered_ip)} rows")

    # ---- Unknown dataset -> 404 ----
    bad = client.get("/api/export/bogus?format=csv")
    ck("unknown dataset 404", bad.status_code == 404, str(bad.status_code))

    # ---- Default format when omitted is CSV ----
    default = client.get("/api/export/credentials")
    ck("default format is csv",
       "text/csv" in default.headers.get("Content-Type", ""),
       default.headers.get("Content-Type", ""))

    db.close()
    if fails:
        print(f"\n{len(fails)} FAILURES: {fails}")
        return 1
    print(f"\nALL {sum(1 for _ in [None])} groups OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
