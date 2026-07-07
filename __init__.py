# LAN Exposure Flow

AegisTrap is configured so LAN users should only interact with the honeypot services:

```text
LAN user / scanner
  -> your PC IP
  -> TCP 2222 fake SSH
  -> TCP 2121 fake FTP
  -> TCP 8080 fake HTTP
  -> TCP 8443 fake HTTPS
```

The dashboard stays private:

```text
your PC only
  -> http://127.0.0.1:5000
```

Do not forward or expose port `5000`. It contains captured sessions, credentials, commands, HTTP requests, and alerts.

## Apply Windows Firewall Rules

Open PowerShell as Administrator from the project folder and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_lan_firewall.ps1
```

That script allows inbound TCP `2222`, `2121`, `8080`, and `8443`, blocks inbound TCP `5000`, blocks the real-service footprint ports shown in your scan, blocks the Windows dynamic RPC range `49152-65535`, and keeps Windows' default inbound policy blocked for Private/Public networks.

If a scan still shows other ports, those ports are being exposed by Windows or another application, not AegisTrap. Review existing inbound allow rules in Windows Defender Firewall.

## Your Nmap Result

The visible honeypot ports were:

```text
2121 FTP trap
2222 SSH trap
8080 HTTP trap
```

The visible real-device footprint included:

```text
80, 443        XAMPP Apache
135, 139, 445 Windows RPC/NetBIOS/SMB
902, 912       VMware auth
3306, 3307     MySQL/MariaDB
33060          MySQL X protocol
49664+         Windows dynamic RPC/app ports
```

To see which local process owns a listening port, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_list_listening_ports.ps1
```
