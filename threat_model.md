# Deployment Guide

## Lab Deployment

1. Install dependencies:

```powershell
pip install -r requirements.txt
```

2. Start AegisTrap:

```powershell
python -m aegistrap
```

3. Open the dashboard locally:

```text
http://127.0.0.1:5000
```

4. From another lab machine:

```bash
ssh -p 2222 root@192.168.1.5
curl http://192.168.1.5:8080/
curl -k https://192.168.1.5:8443/
ftp 192.168.1.5 2121
```

## Windows Firewall

Run as Administrator:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_lan_firewall.ps1
```

This exposes only the honeypot service ports and blocks dashboard access.

## Do Not

- Do not expose dashboard port `5000`.
- Do not run this on your personal daily-use machine for internet exposure.
- Do not forward real Windows service ports.
