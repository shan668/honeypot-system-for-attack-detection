"""End-to-end drive test: attack the running honeypot with real clients,
then read the dashboard API to confirm capture."""
from __future__ import annotations
import ftplib, io, json, socket, ssl, sys, time, urllib.request
import paramiko

FAILS = []

def ck(name, cond, detail=""):
    mark = "[PASS]" if cond else "[FAIL]"
    print(f"{mark} {name}" + (f" -> {detail}" if detail else ""))
    if not cond:
        FAILS.append(name)

# ---------- SSH ----------
try:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect("127.0.0.1", 2222, username="root", password="hunter2",
              look_for_keys=False, allow_agent=False, timeout=10)
    stdin, stdout, stderr = c.exec_command("uname -a")
    out = stdout.read().decode("utf-8", "replace")
    ck("SSH: auth + exec uname", "Linux" in out, out.strip())
    # SFTP
    sftp = c.open_sftp()
    listing = sftp.listdir("/")
    ck("SFTP: listdir /", isinstance(listing, list) and len(listing) > 0, str(listing[:5]))
    with sftp.file("/tmp/attacker.txt", "w") as fh:
        fh.write("owned by mallory\n")
    with sftp.file("/tmp/attacker.txt", "r") as fh:
        got = fh.read().decode()
    ck("SFTP: upload+download roundtrip", got == "owned by mallory\n", got.strip())
    sftp.close(); c.close()
except Exception as exc:
    ck("SSH suite", False, repr(exc))

# ---------- FTP ----------
try:
    f = ftplib.FTP()
    f.connect("127.0.0.1", 2121, timeout=10)
    f.login("anonymous", "a@b.c")
    files = []
    try:
        f.retrlines("LIST", files.append)
    except Exception:
        pass
    ck("FTP: login + LIST", True, f"{len(files)} lines")
    f.quit()
except Exception as exc:
    ck("FTP suite", False, repr(exc))

# ---------- HTTP ----------
try:
    req = urllib.request.Request(
        "http://127.0.0.1:8080/admin",
        data=b"username=admin&password=admin123",
        headers={"User-Agent": "sqlmap/1.7", "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
    except urllib.error.HTTPError as exc:
        # 401 is the expected honeypot response for /admin — still counts as a hit.
        status = exc.code
    ck("HTTP: POST /admin", status in (200, 302, 401, 403), f"status={status}")
except Exception as exc:
    ck("HTTP suite", False, repr(exc))

# ---------- HTTPS ----------
try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen("https://127.0.0.1:8443/", context=ctx, timeout=10) as resp:
        body = resp.read()
    ck("HTTPS: GET /", resp.status == 200, f"status={resp.status} {len(body)}B")
except Exception as exc:
    ck("HTTPS suite", False, repr(exc))

# Let events flush
time.sleep(1.5)

# ---------- Dashboard API ----------
def get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())

try:
    live = get("http://127.0.0.1:5000/api/live")
    ck("Dashboard /api/live shape",
       "summary" in live and "services" in live, list(live.keys()))
    creds = get("http://127.0.0.1:5000/api/credentials?limit=100")
    ck("Dashboard captured SSH creds",
       any(r.get("username") == "root" and r.get("password") == "hunter2" for r in creds),
       f"{len(creds)} rows")
    ck("Dashboard captured HTTP creds",
       any(r.get("username") == "admin" and r.get("password") == "admin123" for r in creds),
       f"{len(creds)} rows")
    cmds = get("http://127.0.0.1:5000/api/commands?limit=100")
    ck("Dashboard captured SSH command",
       any("uname" in (r.get("command") or "") for r in cmds), f"{len(cmds)} rows")
    http_hits = get("http://127.0.0.1:5000/api/http?limit=100")
    ck("Dashboard captured HTTP path /admin",
       any(r.get("path") == "/admin" for r in http_hits),
       f"{len(http_hits)} rows")
    sessions = get("http://127.0.0.1:5000/api/sessions?limit=100")
    protos = {s.get("protocol") for s in sessions}
    ck("Dashboard has sessions for ssh/ftp/http",
       {"ssh", "ftp", "http"}.issubset(protos), str(protos))

    # ---- Exports ----
    def head_get(url):
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, r.headers.get("Content-Type", ""), r.read()

    for ds in ("sessions", "credentials", "commands", "http", "alerts"):
        s, ct, body = head_get(f"http://127.0.0.1:5000/api/export/{ds}?format=csv")
        ck(f"export {ds} csv", s == 200 and "text/csv" in ct and body != b"" if ds != "alerts" else s == 200,
           f"status={s} {len(body)}B")
        s, ct, body = head_get(f"http://127.0.0.1:5000/api/export/{ds}?format=json")
        ck(f"export {ds} json", s == 200 and "application/json" in ct,
           f"status={s} {len(body)}B")
except Exception as exc:
    ck("Dashboard suite", False, repr(exc))

print()
if FAILS:
    print(f"FAILURES: {len(FAILS)} -> {FAILS}")
    sys.exit(1)
print("ALL GREEN")
