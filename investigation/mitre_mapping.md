# MITRE ATT&CK Mapping

## T1078 — Valid Accounts
Successful authentication using the `analyst01` account after multiple failures.

## T1033 — System Owner/User Discovery
`whoami.exe` was executed.

## T1016 — System Network Configuration Discovery
`ipconfig.exe /all` was executed.

## T1059.001 — PowerShell
`powershell.exe` executed `Get-NetTCPConnection`.

## T1049 — System Network Connections Discovery
PowerShell queried TCP connection information.

## T1018 — Remote System Discovery
Multiple internal systems were contacted over SMB.
