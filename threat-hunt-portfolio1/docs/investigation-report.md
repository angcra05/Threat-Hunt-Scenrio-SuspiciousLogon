# Investigation Report — NPT-WS01 Overnight Compromise

**Incident reference:** Help Desk Ticket #4451
**Reported:** 22 April 2026, 09:14 UTC
**Reporter:** Mark Smith, Finance
**Affected host (initial):** NPT-WS01
**Analyst:** Threat Hunt / DFIR Lab Exercise
**Investigation window analyzed:** 22 April 2026, 02:00–08:00 UTC (incident window 04:30–06:00 UTC)

## 1. Summary

The user of NPT-WS01 reported repeated overnight login prompts and dismissed
them as a nuisance. Advanced Hunting analysis of authentication, process,
network, file, and registry telemetry in Microsoft Defender confirmed this
was **not benign**: an external actor authenticated to the host using a
service-desk-style account, executed a remote command via WMI, dropped and
ran an implant, established command-and-control (C2), installed three
independent persistence mechanisms, created a backdoor administrator
account, and moved laterally to a second host.

## 2. Timeline

| # | Time / Order | Event | Evidence |
|---|---|---|---|
| 1 | ~04:30 UTC | Successful interactive-over-network logon to NPT-WS01 using the `helpdeska` account from external IP `20.110.92.50` | `DeviceLogonEvents` |
| 2 | Shortly after | `wmiprvse.exe` spawns `cmd.exe /Q /c start "" "C:\Windows\Temp\WindowsUpdate.exe"` — classic WMI-based remote execution (Impacket `wmiexec` pattern) | `DeviceProcessEvents` |
| 3 | Same window | Implant written to `C:\Windows\Temp\WindowsUpdate.exe`, SHA256 `20cef6a013953890f9d38605d25d60dd63b42b09946bbb18ddb4a456da306e77` | `DeviceFileEvents` |
| 4 | Immediately after | Outbound HTTPS beacon established to `updates.abordasync.website`, resolving to the same actor IP | `DeviceNetworkEvents` |
| 5 | Following minutes | Three persistence mechanisms installed in parallel: Run key `WindowsHealthCheck`, scheduled task `GoogleUpdaterTask`, service `WindowsHealthSvc` | `DeviceRegistryEvents`, `DeviceProcessEvents` |
| 6 | Following minutes | Local account `nexus_admin` created and added to the local Administrators group | `DeviceProcessEvents` |
| 7 | End of window | Lateral-movement indicators observed toward `NPT-SRV01` | `AlertEvidence` / `DeviceInfo` |

## 3. Root Cause / Detection Rationale

The detection point selected — the interactive-over-network logon in
`DeviceLogonEvents` — was chosen because it is the earliest artifact that is
both **anomalous** (a helpdesk-style account authenticating from a public IP
outside business hours) and **low-noise** (authentication events are a small,
high-fidelity table compared to full process or network telemetry), making it
an efficient pivot point for the rest of the chain.

## 4. Impact

- Remote code execution achieved on NPT-WS01
- Three independent persistence mechanisms installed (registry, scheduled task, service)
- A privileged backdoor account created and added to local Administrators
- An active C2 channel established to attacker infrastructure
- Confirmed lateral-movement indicators toward a second host (NPT-SRV01)

## 5. Scope

- **NPT-WS01** — initial access, execution, persistence, C2 origin
- **NPT-SRV01** — secondary host implicated by lateral-movement evidence; requires full triage
- **Accounts:** `helpdeska` (used for initial access), `nexus_admin` (attacker-created, privileged)

## 6. MITRE ATT&CK Mapping

| Stage | Technique | ID |
|---|---|---|
| Initial Access | Valid Accounts | T1078 |
| Execution | Windows Management Instrumentation | T1047 |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 |
| Persistence | Scheduled Task/Job | T1053.005 |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 |
| Privilege Escalation / Persistence | Create Account: Local Account | T1136.001 |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Lateral Movement | Remote Services | T1021 |

## 7. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Account (initial access) | `helpdeska` |
| Account (attacker-created) | `nexus_admin` |
| External IP | `20.110.92.50` |
| C2 Domain | `updates.abordasync.website` |
| File path | `C:\Windows\Temp\WindowsUpdate.exe` |
| SHA256 | `20cef6a013953890f9d38605d25d60dd63b42b09946bbb18ddb4a456da306e77` |
| Registry persistence | `...\CurrentVersion\Run\WindowsHealthCheck` |
| Scheduled task | `GoogleUpdaterTask` |
| Service | `WindowsHealthSvc` |
| Secondary host | `NPT-SRV01` |
