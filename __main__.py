# Roadmap

## Completed Foundations

- Multi-service orchestration
- SQLite persistence
- Local dashboard
- SSH real protocol handshake via Paramiko
- SSH password capture
- SSH PTY/shell and exec request handling
- Per-session virtual Linux filesystem
- Safe Linux command engine
- HTTP realistic portal pages
- HTTP login credential extraction
- HTTPS TLS listener with self-signed cert generation
- FTP command and credential capture
- Clear-data button
- LAN firewall helper

## Next High-Value Work

1. Full FTP data channels
   - PASV
   - PORT
   - RETR
   - STOR
   - realistic upload/download file tracking

2. SFTP and SCP
   - Paramiko SFTP server interface
   - per-session virtual filesystem backend
   - uploaded file hashing and capture metadata

3. Dashboard upgrades
   - live websocket updates
   - CSV/JSON export buttons
   - per-session replay view
   - attacker timeline
   - geolocation and ASN enrichment

4. Detection resistance
   - randomized process IDs
   - randomized uptime
   - randomized latency
   - more realistic package and service inventories

5. Test suite
   - Paramiko SSH integration tests
   - curl/wget HTTP tests
   - HTTPS certificate tests
   - FTP client compatibility tests

6. Future services
   - Telnet
   - SMTP
   - DNS
   - SMB decoy banners
   - MQTT
