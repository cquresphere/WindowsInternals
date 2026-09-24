# Roadmap

This document records the current state of the repository and the plan for extending it with **services**, **processes**, **troubleshooting**, and **diagnostics and monitoring** scripts.

_Last reviewed: 2026-09_

---

## 1. Current state assessment

### Inventory

| Area | Scripts | Notes |
|---|---:|---|
| Security | 16 | Strongest area: Schannel audit and hardening, plus CVE mitigations |
| WinGet | 5 (+1 `.bak`) | Mature: install, repair, manifest metadata |
| Network | 9 (5 in `Download/`) | Firewall report, RPC, TLS for .NET, speed tests |
| Update | 3 | Reset and repair of Windows Update |
| RDP / Identities | 3 | Full RDP audit and remediation framework |
| Other | 8 | BitLocker, SMB, RSAT, Task Scheduler, .NET, Hello, Wi-Fi, ProcMon |
| **Total** | **~45 files, ~9,200 lines** | |

### Strengths

- Covers real operational problems, and most scripts link to the Microsoft KB or advisory they implement.
- The newer scripts are production quality: comment-based help, parameters, `SupportsShouldProcess`, and JSON/HTML reports. Examples are `Invoke-RDPHardening.ps1`, `Test-SchannelSecurity.ps1`, `Harden-SchannelSecurity-MS.ps1`, `Repair-WinGetSources.ps1` and `Install-WinGetUltimate.ps1`.
- The folders follow a clear per-technology structure.

### Gaps and technical debt

| # | Finding | Impact |
|---|---|---|
| 1 | Only 8 of ~40 scripts have comment-based help, and only 8 use `[CmdletBinding()]` | You cannot discover them with `Get-Help`, and they don't support `-Verbose`/`-WhatIf` |
| 2 | Most scripts hard-code their values (paths such as `C:\Temp`, server names, port ranges, package IDs) | You have to edit the script before you can use it |
| 3 | `Test-RegistryValue` is copy-pasted into ~11 scripts in 3 incompatible variants (`-Path/-Value` vs `-key/-value`) | Duplication and drift |
| 4 | Only 5 scripts declare `#Requires -RunAsAdministrator` | They fail partway through when run without elevation |
| 5 | `Get-WmiObject` is used in 4 scripts | It was removed in PowerShell 7, so use `Get-CimInstance` |
| 6 | No LICENSE file | Others cannot legally reuse the code |
| 7 | No linting, tests or CI | Regressions go unnoticed |
| 8 | Repo hygiene: `WinGet/Install-WinGetUltimate.ps1.bak` is committed, `Set-ProcMonAltitude` has no `.ps1` extension and sits in the root, and there are typos in file names (`Get-CipherSuitReport`, `Check-AnyCipherSuiteIsConfiguedByGPO`, `Test-DownloadSpeed_BitsTransfrer`, `_NaitiveAPI`) | Looks unprofessional and makes scripts harder to find |
| 9 | Several verbs are unapproved (`Check-`, `Fix-`, `Mitigate-`, `Harden-`, `Bypass-`) | PSScriptAnalyzer warnings, and inconsistent naming |

### Confirmed bugs

| Script | Problem |
|---|---|
| `Network/Disable-IPv6.ps1` | Calls `Test-RegistryValue`, which is never defined, so the script fails at runtime |
| `Network/Download/Test-DownloadSpeed_InvokeRestMethod.ps1` | Checks `$PathToCSFile`, which is undefined (copy-paste leftover) |
| `Update/Fix-UpdateError0x800f0922.ps1` | The failure banner prints `$RemovedPackages` instead of `$ErrorPackages`. `$null -ne @()` is always true, so both banners always print. The script also overwrites the automatic `$matches` variable |
| `BitLocker/Get-BitLockerStatus.ps1` | Tries to `Install-Module BitLocker`, but that module ships with Windows and isn't in the Gallery. With more than one volume, the `-eq` comparisons run against arrays and give wrong results |
| `Security/Disable-CachedLogonCredential.ps1` | No elevation check and no confirmation, although the change affects offline logon |

---

## 2. Development plan

### Phase 0 — Foundation and hygiene _(do first; small effort)_

- [ ] Add a `LICENSE` (MIT recommended for script collections).
- [ ] Fix the confirmed bugs listed above.
- [ ] Remove `Install-WinGetUltimate.ps1.bak` (git history keeps it). Rename `Set-ProcMonAltitude` to `Diagnostics/Set-ProcMonAltitude.ps1`.
- [ ] Readability cleanup: `if(-not-(Test-Path …))` in `Network/Download/*_NaitiveAPI.ps1` and `*_InvokeRestMethod.ps1` is valid PowerShell but hard to read. Rewrite it as `if (-not (Test-Path …))`.
- [ ] Fix the file-name typos. Consider approved verbs in names (`Fix-` → `Repair-`, `Check-` → `Test-`, `Mitigate-`/`Harden-` → `Set-`/`Enable-`/`Protect-`).
- [ ] Add `.gitignore`, `.editorconfig` (UTF-8 with BOM for PS 5.1 compatibility, CRLF), and `PSScriptAnalyzerSettings.psd1`.
- [ ] Add `templates/Script-Template.ps1` with the standard skeleton: comment-based help, `#Requires`, `CmdletBinding(SupportsShouldProcess)`, parameters, logging and object output.
- [ ] Add a GitHub Actions workflow on `windows-latest` that runs PSScriptAnalyzer and Pester.

### Phase 1 — Services toolkit _(new folder: `Services/`)_

| Script | Purpose |
|---|---|
| `Get-ServiceReport.ps1` | Inventories all services with start mode, state, account, binary path, delayed-start and trigger-start flags, and dependencies. Exports to CSV, HTML or Excel. |
| `Test-ServiceSecurity.ps1` | Audits services for **unquoted service paths**, writable service binaries and folders, weak service DACLs (via `sc sdshow`), and services running as LocalSystem that don't need to. |
| `Get-ServiceFailureConfig.ps1` / `Set-ServiceRecovery.ps1` | Reads and sets recovery actions (restart, run program, reset counter) for critical services. |
| `Get-ServiceDependencyTree.ps1` | Shows the dependency tree (and reverse tree) of a service, to answer "what breaks if I stop X?". |
| `Watch-Service.ps1` | Monitors a set of services, restarts any that stop within limits, and logs to the Event Log or a file. Can be installed as a scheduled task. |
| `Get-ServiceCrashHistory.ps1` | Parses SCM events 7031, 7034, 7023 and 7000/7009 (unexpected termination, start timeouts) into a timeline. |
| `Compare-ServiceBaseline.ps1` | Exports a JSON baseline and reports drift: new services, changed start mode or account. Useful for detecting persistence. |

### Phase 2 — Processes toolkit _(new folder: `Processes/`)_

| Script | Purpose |
|---|---|
| `Get-ProcessDetail.ps1` | Rich process view: parent PID, command line, owner, session, integrity level, signature status, file hash and loaded-module count. |
| `Get-ProcessTree.ps1` | Parent/child tree, including orphans. Flags suspicious lineage (for example Office → `cmd`/`powershell`). |
| `Get-TopResourceConsumer.ps1` | Top N processes by CPU %, working set, private bytes, handles, threads and I/O, sampled over time to spot trends. |
| `Find-ProcessLeak.ps1` | Samples handle, GDI/USER object and private-bytes counts over time and flags steady growth (leak detection). |
| `Get-ProcessNetworkConnection.ps1` | Maps `Get-NetTCPConnection`/`Get-NetUDPEndpoint` to processes and services, with optional reverse DNS. |
| `Find-LockingProcess.ps1` | Finds which process holds a file or folder open (Restart Manager API, with `handle.exe` as a fallback). |
| `Test-ProcessSignature.ps1` | Lists running processes and loaded DLLs that are unsigned or have an invalid Authenticode signature. |
| `New-ProcessDump.ps1` | Captures a memory dump of a hung or crashing process with ProcDump, or with `MiniDumpWriteDump` if ProcDump isn't available. |

### Phase 3 — Troubleshooting toolkit _(new folder: `Troubleshooting/`)_

| Script | Purpose |
|---|---|
| `Invoke-SystemHealthCheck.ps1` | One-shot triage: uptime, pending reboot, disk space, memory pressure, stopped automatic services, recent critical events, time sync, domain trust and Defender status. HTML summary. |
| `Test-PendingReboot.ps1` | Checks every pending-reboot source (CBS, WU, PendingFileRenameOperations, SCCM, domain join, computer rename). |
| `Repair-SystemImage.ps1` | Runs `DISM /RestoreHealth` then `SFC /scannow`, with optional source media and parsed CBS/DISM logs. |
| `Get-BootPerformance.ps1` | Parses Diagnostics-Performance events 100, 101 and 200 to find slow boot and logon, and the drivers and services that cause it. |
| `Get-BSODAnalysis.ps1` | Lists bugchecks (event 1001, minidumps) with stop codes and faulting modules. Optionally runs `kd -z <dump> -c "!analyze -v"` when the Debugging Tools are installed. |
| `Get-AppCrashReport.ps1` | Aggregates Application Error (1000) and Windows Error Reporting events by faulting application and module. |
| `Test-NetworkConnectivity.ps1` | Layered checks: adapter, IP/DHCP, gateway, DNS resolution, proxy/WinHTTP, TCP port tests, MTU and path. |
| `Test-DomainHealth.ps1` | Checks secure channel (`Test-ComputerSecureChannel`), DC locator (`nltest`), Kerberos time skew, SYSVOL/NETLOGON access, and gpresult errors. |
| `Get-GroupPolicyDiagnostic.ps1` | Reports GP processing time, failures (GroupPolicy/Operational log) and the applied GPOs. |
| `New-DiagnosticBundle.ps1` | Collects event logs, `systeminfo`, `ipconfig /all`, `gpresult /h`, installed updates, driver list, CBS and WU logs, and services into a zip for escalation. |
| `Reset-NetworkStack.ps1` | Resets Winsock, TCP/IP and DNS cache, and optionally re-enables adapters (with `-WhatIf`). |
| `Repair-WMIRepository.ps1` | Verifies the WMI repository (`winmgmt /verifyrepository`) and salvages or rebuilds it only when it is inconsistent. |

### Phase 4 — Diagnostics and monitoring _(new folder: `Monitoring/`)_

| Script | Purpose |
|---|---|
| `Get-PerformanceSnapshot.ps1` | Takes a quick snapshot of key counters: CPU, queue length, memory available and committed, paging, disk latency and queue, network errors. Applies thresholds and returns a RAG status. |
| `Start-PerfCounterCollection.ps1` / `Stop-…` | Creates and starts a `logman` data collector set (BLG) with a standard counter set, for long-running captures. |
| `Start-WPRTrace.ps1` | Wraps Windows Performance Recorder with CPU, disk I/O, file I/O and wait-analysis profiles for deep analysis in WPA. |
| `Watch-EventLog.ps1` | Subscribes to or polls selected event IDs (for example 4625, 4740, 7031, 41 or 6008) and alerts to the console, a file, email or a webhook. |
| `Get-SecurityEventSummary.ps1` | Summarizes failed logons, lockouts, privileged logons (4672), new services (7045), scheduled task creation (4698) and log clearing (1102). |
| `Test-DiskHealth.ps1` | Reports SMART and reliability counters (`Get-StorageReliabilityCounter`), free space trends, and NTFS or disk errors from the System log. |
| `Get-ReliabilityHistory.ps1` | Exports Reliability Monitor data (`Win32_ReliabilityRecords`) and the stability index. |
| `Get-UptimeAndRebootHistory.ps1` | Reboot and shutdown timeline from events 6005, 6006, 6008, 1074 and 41, with the reasons and initiating users. |
| `Test-CertificateExpiry.ps1` | Scans the machine and user certificate stores (and optionally remote TLS endpoints) for certificates that are expiring or expired. |
| `Invoke-HealthDashboard.ps1` | Combines the outputs above into a single static HTML dashboard. Can run as a scheduled task. |

### Phase 5 — Quality and packaging _(ongoing)_

- [ ] **Shared helper module** (`Modules/WindowsInternals.Common/`): `Test-RegistryValue`, `Set-RegistryValueSafe` (with backup and `-WhatIf`), `Test-IsAdmin`, `Write-Log`, `Export-Report` (CSV/JSON/HTML/Excel) and `Get-OSInfo`. Keep individual scripts runnable standalone by dot-sourcing the helper or falling back to inline code.
- [ ] **Pester tests** for pure logic (parsers such as `WinGetShowToPSObject` and `Fix-UpdateError` regexes, the report builders) and mocked registry tests for the hardening scripts.
- [ ] **Retrofit legacy scripts**, starting with the most-used and highest-impact ones: comment-based help, parameters instead of hard-coded values, `SupportsShouldProcess` and `#Requires`, and `Get-CimInstance` instead of `Get-WmiObject`.
- [ ] **Remote execution:** add a `-ComputerName`/`-Session` parameter to the reporting scripts through `Invoke-Command`.
- [ ] **Optional:** publish the toolkits as a module on the PowerShell Gallery, and sign the scripts with a code-signing certificate.

---

## 3. Suggested order of work

1. **Phase 0.** It unblocks everything else and fixes real bugs.
2. **Phase 3:** `Invoke-SystemHealthCheck`, `Test-PendingReboot`, `New-DiagnosticBundle`. These give the most value per script.
3. **Phases 1 and 2:** the core Services and Processes scripts (`Get-ServiceReport`, `Test-ServiceSecurity`, `Get-ProcessDetail`, `Get-ProcessTree`, `Get-TopResourceConsumer`).
4. **Phase 4:** the monitoring scripts and the HTML dashboard.
5. **Phase 5:** continuously, with every new script meeting the template and CI standards from day one.
