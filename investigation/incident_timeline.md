# Incident Timeline

## 09:41–09:42 — Authentication
- analyst01 experienced multiple failed authentication attempts
- Source IP: 10.10.10.50
- Followed by successful authentication

## 09:42 — Internal Network Activity
- 10.10.10.50 connected to multiple internal hosts over TCP/445 (SMB)
- Some connections were allowed
- One SMB connection was blocked

## 09:42–09:43 — Endpoint Discovery
- cmd.exe executed
- whoami.exe executed
- ipconfig.exe executed
- PowerShell executed (PID 4216)

## 09:43 — DNS / Process Correlation
- PowerShell spawned nslookup.exe (PID 4252)
- nslookup queried updates-example.com
- DNS telemetry confirmed the same query

## 09:43 — Remote Access Attempt
- 10.10.10.50 attempted TCP/3389 to 10.10.10.20
- Firewall action: BLOCKED

## 09:43 — HTTPS Activity
- 10.10.10.50 → 10.10.10.20:443
- Firewall action: ALLOWED

## 09:45 — Additional DNS Activity
- analyst01 queried updates-example.com again
