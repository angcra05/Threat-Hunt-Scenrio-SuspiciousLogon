# Containment & Remediation Plan — NPT-WS01 / NPT-SRV01

Based on findings in [`investigation-report.md`](./investigation-report.md).

## 1. Isolate

- Isolate **NPT-WS01** immediately — point of initial access and C2 origin.
- Isolate **NPT-SRV01** immediately — implicated by lateral-movement evidence.
- Isolating both hosts first prevents any further attacker action while the
  remaining steps are executed.

## 2. Disable compromised identities

- Disable the `helpdeska` account (or reset credentials and force MFA
  re-enrollment if it must remain active) — this was the initial-access
  vector.
- Disable the attacker-created `nexus_admin` local account and remove it
  from the local Administrators group.

## 3. Remove persistence

Remove all three mechanisms the attacker installed in parallel:

- Registry Run key: `...\CurrentVersion\Run\WindowsHealthCheck`
- Scheduled task: `GoogleUpdaterTask`
- Windows service: `WindowsHealthSvc`

## 4. Block known indicators of compromise

- Block external IP `20.110.92.50` at the perimeter/firewall.
- Block/sinkhole the domain `updates.abordasync.website`.
- Add SHA256 `20cef6a013953890f9d38605d25d60dd63b42b09946bbb18ddb4a456da306e77`
  to the Defender for Endpoint blocklist (and any EDR/AV blocklists in use).

## 5. Eradicate the artifact

- Remove `C:\Windows\Temp\WindowsUpdate.exe` from NPT-WS01.
- This step is sequenced **after** blocklisting so the hash and network
  indicators are already fielded before local traces are cleared —
  preserving the ability to detect the same artifact elsewhere first.

## 6. Hunt across the environment

- Sweep the full fleet (not just the `npt-*` hosts) for the same file hash,
  C2 domain, registry value, scheduled task name, and service name before
  considering the incident closed — the goal is to rule out a broader
  compromise, not just clean the two known hosts.

## 7. Recommendations

- Require MFA on all service-desk / shared accounts, particularly for
  network-type logons.
- Alert on `wmiprvse.exe` spawning `cmd.exe` with a `/Q /c start` pattern —
  it is a well-known Impacket `wmiexec` fingerprint.
- Alert on scheduled tasks/services with names that closely mimic
  legitimate updater/health-check processes (e.g. `GoogleUpdaterTask`,
  `WindowsHealthCheck`) but do not match the vendor's real task/service
  naming or binary path.
