# SOC Alert Triage & Incident Investigation Report

## 1. Executive Summary

A suspicious authentication and endpoint activity sequence was identified for the account `analyst01` originating from `10.10.10.50`.

The activity included multiple failed authentication attempts followed by successful authentication, endpoint discovery commands, PowerShell execution, DNS reconnaissance, SMB connections to internal systems, and a blocked RDP connection.

The investigation correlated endpoint and DNS telemetry to identify a query for `updates-example.com`. Network telemetry also showed an attempted RDP connection to `10.10.10.20` that was blocked by the firewall.

The activity was assessed as suspicious and requiring further investigation for potential account compromise or unauthorized internal reconnaissance. No definitive evidence of successful compromise was established from the available telemetry.

---

## 2. Incident Details

| Field | Details |
|---|---|
| Investigated User | `analyst01` |
| Source IP | `10.10.10.50` |
| Primary Host | `WIN-SOC-01` |
| Suspicious Domain | `updates-example.com` |
| RDP Target | `10.10.10.20` |
| RDP Port | `3389/TCP` |
| RDP Action | Blocked |
| Investigation Platform | Splunk Cloud |
| Data Source | Synthetic SOC telemetry |
| Severity | Medium |
| Assessment | Suspicious activity requiring further investigation |

---

## 3. Investigation Summary

The investigation began with authentication telemetry associated with `analyst01`.

The account experienced multiple failed authentication attempts from `10.10.10.50`, followed by successful authentication events.

Post-authentication endpoint activity included:

- `cmd.exe`
- `whoami.exe`
- `ipconfig.exe`
- `powershell.exe`
- `nslookup.exe`

The PowerShell process was associated with PID `4216`. PowerShell subsequently spawned `nslookup.exe`, associated with PID `4252`.

The `nslookup.exe` activity was correlated with DNS telemetry showing queries for `updates-example.com`.

Network telemetry from `10.10.10.50` showed multiple SMB connections over TCP/445, an attempted RDP connection over TCP/3389, an HTTPS connection over TCP/443, and DNS traffic over UDP/53.

---

## 4. Key Evidence

### Authentication Activity

The authentication investigation identified:

- User: `analyst01`
- Source IP: `10.10.10.50`
- Multiple failed authentication attempts
- Successful authentication following the failures

This pattern was considered suspicious because successful authentication occurred after repeated failures.

### Endpoint Activity

Following authentication, endpoint telemetry showed several discovery-related commands:

- `whoami.exe` — user/account discovery
- `ipconfig.exe` — network configuration discovery
- `powershell.exe` — PowerShell execution
- `nslookup.exe` — DNS lookup activity

The PowerShell process was associated with PID `4216`.

The `nslookup.exe` process was associated with PID `4252` and had PowerShell as its parent process.

### DNS Correlation

At approximately `09:43:38`, endpoint telemetry recorded `nslookup.exe` activity while DNS telemetry recorded a query for:

`updates-example.com`

Both events were associated with:

- User: `analyst01`
- Source IP: `10.10.10.50`

This provided a direct endpoint-to-DNS correlation.

### Network Activity

Network telemetry showed:

| Destination | Port | Protocol | Action |
|---|---:|---|---|
| `10.10.10.20` | 445 | TCP | Allowed |
| `10.10.10.21` | 445 | TCP | Allowed |
| `10.10.10.22` | 445 | TCP | Allowed |
| `10.10.10.23` | 445 | TCP | Blocked |
| `10.10.10.20` | 3389 | TCP | Blocked |
| `10.10.10.20` | 443 | TCP | Allowed |
| `10.10.10.30` | 53 | UDP | Allowed |

The TCP/3389 connection is particularly notable because port 3389 is commonly used for Remote Desktop Protocol (RDP). The connection to `10.10.10.20` was blocked.

The TCP/445 connections represent SMB activity and included connections to multiple internal hosts.

---

## 5. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Valid Accounts | T1078 | Successful authentication using `analyst01` |
| System Owner/User Discovery | T1033 | `whoami.exe` |
| System Network Configuration Discovery | T1016 | `ipconfig.exe` |
| Command and Scripting Interpreter: PowerShell | T1059.001 | `powershell.exe` |
| System Network Connections Discovery | T1049 | PowerShell network connection discovery |
| Remote System Discovery | T1018 | SMB connections to multiple internal systems |

These mappings describe behaviors observed during the investigation and do not by themselves prove malicious intent.

---

## 6. Indicators of Interest

### Host / Network Indicators

- Source IP: `10.10.10.50`
- Destination IP: `10.10.10.20`
- Destination IP: `10.10.10.21`
- Destination IP: `10.10.10.22`
- Destination IP: `10.10.10.23`
- Suspicious domain: `updates-example.com`
- RDP port: `3389/TCP`
- SMB port: `445/TCP`

### Process Indicators

- `powershell.exe`
- `nslookup.exe`
- `whoami.exe`
- `ipconfig.exe`

### Process IDs

- PowerShell PID: `4216`
- nslookup PID: `4252`

---

## 7. Detection Logic

The investigation also produced a detection query designed to identify users experiencing multiple authentication failures followed by a successful authentication.

The detection looks for:

- At least four authentication failures
- At least one successful authentication
- The associated user and source IP
- Related processes, DNS queries, and destination ports

The detection logic is stored in:

`spl/final_detection.spl`

---

## 8. Analyst Assessment

### Severity: Medium

The activity was classified as Medium severity because several suspicious behaviors occurred within the same investigation window:

1. Multiple failed authentication attempts were followed by successful authentication.
2. Discovery commands were executed after authentication.
3. PowerShell was used to perform network-related activity.
4. `nslookup.exe` queried `updates-example.com`.
5. SMB connections were made to multiple internal systems.
6. An RDP connection attempt to `10.10.10.20` was blocked.

However, the available telemetry does not establish that the account was compromised or that malicious code executed successfully.

The blocked RDP connection is also an important containment indicator because the attempted connection did not succeed according to the available firewall telemetry.

---

## 9. Recommended SOC Response

If this were a real enterprise incident, the following actions would be appropriate:

1. Validate the authentication activity with the user.
2. Review the `analyst01` account for unauthorized activity.
3. Temporarily reset or disable the account if compromise is suspected.
4. Investigate the endpoint `WIN-SOC-01` for additional process and persistence activity.
5. Investigate `updates-example.com` using approved threat-intelligence sources.
6. Review SMB activity involving the contacted internal systems.
7. Investigate the attempted RDP connection to `10.10.10.20`.
8. Search the environment for additional activity involving `10.10.10.50` and `updates-example.com`.
9. Continue monitoring for repeated authentication failures or additional suspicious network activity.

---

## 10. Conclusion

The investigation successfully demonstrated a SOC alert-triage workflow using Splunk Cloud.

Authentication, endpoint, DNS, and network telemetry were correlated to reconstruct a suspicious activity sequence involving the `analyst01` account.

The investigation identified multiple discovery behaviors, PowerShell execution, DNS activity involving `updates-example.com`, internal SMB activity, and a blocked RDP attempt.

The evidence supports treating the activity as suspicious and worthy of further investigation, while avoiding an unsupported conclusion that the system or account was definitively compromised.

This lab demonstrates practical skills in SIEM investigation, event correlation, timeline reconstruction, IOC identification, MITRE ATT&CK mapping, detection development, and incident assessment.
