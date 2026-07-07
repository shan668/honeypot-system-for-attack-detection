# Threat Model

## Assets Protected

- Host operating system
- Real filesystem
- Real credentials
- Dashboard data
- Local network services not part of the honeypot

## Main Safety Controls

- Attacker commands are never passed to `cmd.exe`, PowerShell, bash, or Python eval.
- SSH shell uses `CommandEngine` and `VirtualSessionState`.
- Virtual filesystem is in memory and scoped per session.
- Dashboard binds to `127.0.0.1` unless explicitly overridden.
- Windows firewall helper exposes only honeypot ports.

## Known Limitations

- FTP currently captures commands and credentials but does not yet implement
full passive/active data transfer for all clients.
- SFTP/SCP protocol support is not complete yet.
- HTTPS uses a self-signed certificate, which browsers will warn about.
- This is for authorized labs, not unsupervised internet deployment.

## Defensive Assumptions

- Run inside an isolated lab VM or dedicated test machine.
- Do not store personal files or secrets on the honeypot host.
- Do not expose the dashboard publicly.
- Monitor disk usage if collecting long-term logs.
