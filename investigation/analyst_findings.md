# Analyst Findings

## Initial Finding

Multiple failed authentication attempts were observed for `analyst01` from `10.10.10.50`, followed by successful authentication.

Post-authentication activity included:
- `whoami.exe`
- `ipconfig.exe`
- `powershell.exe`
- `nslookup.exe`

The endpoint and DNS telemetry correlated `nslookup.exe` with a query for `updates-example.com`.

Network telemetry also showed SMB activity and a blocked RDP connection to `10.10.10.20`.

## Current Assessment

The activity is suspicious and warrants investigation for possible account compromise or unauthorized internal reconnaissance.

No definitive evidence of successful compromise has been established yet.
