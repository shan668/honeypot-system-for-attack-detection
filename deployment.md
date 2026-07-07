# AegisTrap configuration
# All values can be overridden via environment variables (AEGISTRAP_*).

general:
  project_name: AegisTrap
  version: 1.0.0
  log_level: INFO

# ---------------------------------------------------------------------------
# Service listeners
# ---------------------------------------------------------------------------
ssh:
  name: ssh
  protocol: ssh
  enabled: true
  listen_host: 0.0.0.0
  listen_port: 2222
  banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  max_concurrent: 50
  session_timeout: 300

ftp:
  name: ftp
  protocol: ftp
  enabled: true
  listen_host: 0.0.0.0
  listen_port: 2121
  banner: "vsftpd 3.0.5"
  max_concurrent: 50
  session_timeout: 300

http:
  name: http
  protocol: http
  enabled: true
  listen_host: 0.0.0.0
  listen_port: 8080
  banner: "Apache/2.4.57 (Ubuntu)"
  max_concurrent: 100
  session_timeout: 120

https:
  name: https
  protocol: https
  enabled: true
  listen_host: 0.0.0.0
  listen_port: 8443
  banner: "Apache/2.4.57 (Ubuntu)"
  max_concurrent: 100
  session_timeout: 120

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
dashboard:
  enabled: true
  host: 127.0.0.1
  port: 5000
  secret_key: ""
  debug: false
  refresh_interval_ms: 5000

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging:
  directory: logs
  level: INFO
  max_bytes: 10485760   # 10 MiB per file
  backup_count: 10
  console: true

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
database:
  path: data/aegistrap.db
  pool_size: 5
  enable_wal: true

# ---------------------------------------------------------------------------
# Threat engine
# ---------------------------------------------------------------------------
threat:
  window_seconds: 60
  failed_login_threshold: 5
  request_rate_threshold: 100
  directory_bruteforce_threshold: 30
  unique_user_threshold: 10
  credential_stuffing_threshold: 15
  ssh_command_threshold: 50
  ftp_command_threshold: 100
  auto_block_threshold: 200

# ---------------------------------------------------------------------------
# Honeypot persona
# ---------------------------------------------------------------------------
fake_hostname: edge-router-01

fake_users:
  - root
  - admin
  - user
  - test
  - ubuntu
  - pi
  - oracle
  - postgres
  - ftpuser
  - guest
  - support
  - administrator
  - service
  - webmaster
  - student
  - info
  - marketing

fake_passwords:
  - admin
  - password
  - 123456
  - root
  - toor
  - letmein
  - qwerty
  - P@ssw0rd
  - changeme
  - welcome
  - test
  - default
  - 12345
  - alpine
  - raspberry
  - ubuntu

fake_filelist:
  - name: README.md
    size: "1024"
    type: file
  - name: backup.tar.gz
    size: "2097152"
    type: file
  - name: logs
    size: "0"
    type: dir
  - name: configs
    size: "0"
    type: dir
  - name: data
    size: "0"
    type: dir
  - name: scripts
    size: "0"
    type: dir
