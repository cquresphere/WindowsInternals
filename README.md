# WindowsInternals

> PowerShell scripts for administering, hardening, troubleshooting and auditing Windows clients and servers.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-5391FE?logo=powershell&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20%7C%20Server%202016%2B-0078D6?logo=windows&logoColor=white)

This repository collects scripts I use in day-to-day Windows administration. They cover security hardening and CVE mitigations, TLS/Schannel auditing, RDP hardening, WinGet deployment and repair, Windows Update troubleshooting, and reporting. Most scripts are standalone `.ps1` files. You can run them one at a time, and they have no dependencies on each other.

---

## Table of contents

- [Quick start](#quick-start)
- [Requirements](#requirements)
- [Script catalog](#script-catalog)
- [Safety and usage guidelines](#safety-and-usage-guidelines)
- [Repository conventions](#repository-conventions)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

---

## Quick start

```powershell
# 1. Clone the repository
git clone https://github.com/cquresphere/WindowsInternals.git
cd WindowsInternals

# 2. Unblock the downloaded files (removes the Mark-of-the-Web)
Get-ChildItem -Recurse -Filter *.ps1 | Unblock-File

# 3. Allow local scripts for the current session only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 4. Read the script's help before running it
Get-Help .\Security\Test-SchannelSecurity.ps1 -Full

# 5. Run it (most scripts need an elevated session)
.\Security\Test-SchannelSecurity.ps1 -OutputFormat HTML
```

> [!TIP]
> Scripts that declare `SupportsShouldProcess` accept `-WhatIf`. Use it to see what the script would change before you apply it. These include `Invoke-RDPHardening.ps1`, `Harden-SchannelSecurity-MS.ps1` and `Repair-WinGetSources.ps1`.

## Requirements

| Requirement | Details |
|---|---|
| Operating system | Windows 10 / 11, Windows Server 2016 or newer (some scripts support 2012 R2) |
| PowerShell | Windows PowerShell 5.1. Many scripts also run on PowerShell 7.x |
| Privileges | Most scripts change HKLM, services or system features, so run them as **Administrator** |
| Optional modules | [`ImportExcel`](https://www.powershellgallery.com/packages/ImportExcel), used by the Excel report scripts |

## Script catalog

Legend: 🔍 read-only / reporting · 🛠️ changes system configuration · ⚠️ high impact (review carefully, test first)

### 🔐 Security: hardening and vulnerability mitigations

| Script | Type | Description |
|---|:---:|---|
| [`Test-SchannelSecurity.ps1`](Security/Test-SchannelSecurity.ps1) | 🔍 | Audits Schannel protocols, ciphers, hashes, key exchange, cipher suite order, and .NET/WinHTTP TLS settings. Reports to the console, HTML or JSON. |
| [`Harden-SchannelSecurity-MS.ps1`](Security/Harden-SchannelSecurity-MS.ps1) | ⚠️ | Applies Schannel TLS/SSL hardening based on Microsoft guidance and IISCrypto best practices, with a registry backup. |
| [`Disable-WeakOutdatedProtocols.ps1`](Security/Disable-WeakOutdatedProtocols.ps1) | ⚠️ | Disables SSL 2.0/3.0 and TLS 1.0/1.1. |
| [`Get-CipherSuitReport.ps1`](Security/Get-CipherSuitReport.ps1) | 🔍 | Exports the enabled TLS cipher suites to an Excel report. |
| [`Check-AnyCipherSuiteIsConfiguedByGPO.ps1`](Security/Check-AnyCipherSuiteIsConfiguedByGPO.ps1) | 🔍 | Detects whether Group Policy controls the cipher suite order. |
| [`Set-LDAPEnforceChannelBinding.ps1`](Security/Set-LDAPEnforceChannelBinding.ps1) | ⚠️ | Enforces LDAP channel binding on domain controllers (KB4034879). |
| [`Disable-NullSession.ps1`](Security/Disable-NullSession.ps1) | 🛠️ | Restricts anonymous (null session) access through LSA settings. |
| [`Disable-CachedLogonCredential.ps1`](Security/Disable-CachedLogonCredential.ps1) | ⚠️ | Sets `CachedLogonsCount` to 0. Offline domain logon will stop working. |
| [`Disable-AutoRun.ps1`](Security/Disable-AutoRun.ps1) | 🛠️ | Disables AutoRun on all drives (STIG V-63673). |
| [`Mitigate-Spectre&MeltdownVulnerabilities.ps1`](Security/Mitigate-Spectre&MeltdownVulnerabilities.ps1) | ⚠️ | Applies the speculative-execution mitigations for the detected CPU vendor (KB4072698). |
| [`Mitigate-WinVerifyTrustSignatureValidationVulnerability.ps1`](Security/Mitigate-WinVerifyTrustSignatureValidationVulnerability.ps1) | 🛠️ | Enables the certificate padding check (CVE-2013-3900). |
| [`CVE-2017-8529-Mitigation.ps1`](Security/CVE-2017-8529-Mitigation.ps1) | 🛠️ | Mitigates the IE/Edge print information disclosure vulnerability. |
| [`CVE-2020-1350-Mitigation.ps1`](Security/CVE-2020-1350-Mitigation.ps1) | 🛠️ | Applies the SIGRed DNS Server workaround (`TcpReceivePacketSize`). |
| [`Fix-ADV200013.ps1`](Security/Fix-ADV200013.ps1) | 🛠️ | Mitigates DNS cache poisoning (`MaximumUdpPacketSize`). |
| [`CVE-2021-43890-Mitigation.ps1`](Security/CVE-2021-43890-Mitigation.ps1) | 🛠️ | Mitigates the AppX Installer spoofing vulnerability (ms-appinstaller protocol). |
| [`CVE-2023-36884-Mitigation.ps1`](Security/CVE-2023-36884-Mitigation.ps1) | 🛠️ | Applies the Office/HTML RCE feature-control mitigation. |

### 🖥️ Remote Desktop

| Script | Type | Description |
|---|:---:|---|
| [`Invoke-RDPHardening.ps1`](RDP/Invoke-RDPHardening.ps1) | ⚠️ | Audits and optionally remediates RDP settings: NLA, TLS, encryption level, firewall scoping and user rights. Reports to JSON or HTML. |
| [`Set-RDPShortcut.ps1`](RDP/Set-RDPShortcut.ps1) | 🛠️ | Generates a pre-configured `.rdp` connection file. |
| [`Get-RemoteDesktopSessions.ps1`](Identities/Get-RemoteDesktopSessions.ps1) | 🔍 | Lists the active RDP logon sessions (LogonType 10) and their users. |

### 🌐 Network

| Script | Type | Description |
|---|:---:|---|
| [`Get-AllWindowsDefenderFirewallRules.ps1`](Network/Get-AllWindowsDefenderFirewallRules.ps1) | 🔍 | Collects firewall rules from every policy store in parallel runspaces and exports them to Excel. |
| [`Set-RPCDynamicPortRange.ps1`](Network/RPC/Set-RPCDynamicPortRange.ps1) | ⚠️ | Restricts the RPC dynamic port range, for example to allow it through a firewall. |
| [`Enable-DotNET-TLS12.ps1`](Network/Enable-DotNET-TLS12.ps1) | 🛠️ | Enables `SchUseStrongCrypto` and `SystemDefaultTlsVersions` for .NET 2.0 and 4.x. |
| [`Disable-IPv6.ps1`](Network/Disable-IPv6.ps1) | ⚠️ | Unbinds IPv6 from all adapters and sets `DisabledComponents`. |
| [`Network/Download/`](Network/Download) | 🔍 | Compares download speed across BITS, `Invoke-WebRequest`, `Invoke-RestMethod`, `HttpClient` and native WinHTTP. |

### 💾 Storage and BitLocker

| Script | Type | Description |
|---|:---:|---|
| [`Set-SecureSMBSettings.ps1`](Storage/Set-SecureSMBSettings.ps1) | ⚠️ | Disables SMBv1 and enforces a secure SMBv2/v3 configuration (signing, encryption). |
| [`Get-BitLockerStatus.ps1`](BitLocker/Get-BitLockerStatus.ps1) | 🔍 | Reports BitLocker protection and encryption status. |

### 📦 WinGet

| Script | Type | Description |
|---|:---:|---|
| [`Install-WinGetUltimate.ps1`](WinGet/Install-WinGetUltimate.ps1) | 🛠️ | Installs WinGet with dependency handling, SYSTEM-context support and several fallback methods. |
| [`Install-WinGetWithDependenciesAndLicense.ps1`](WinGet/Install-WinGetWithDependenciesAndLicense.ps1) | 🛠️ | A simpler installer for WinGet, its dependencies and license. |
| [`Repair-WinGetSources.ps1`](WinGet/Repair-WinGetSources.ps1) | 🛠️ | Detects and repairs a broken or stale `winget` community source. |
| [`WingetManifestMetadata.ps1`](WinGet/WingetManifestMetadata.ps1) | 🔍 | Resolves installer URLs and SHA256 hashes from `microsoft/winget-pkgs`. You can run it directly or dot-source it as a library. |
| [`WinGetShowToPSObject.ps1`](WinGet/WinGetShowToPSObject.ps1) | 🔍 | Parses `winget show` output into a PowerShell object. |

### 🔄 Windows Update

| Script | Type | Description |
|---|:---:|---|
| [`Reset-UpdateComponents.ps1`](Update/Reset-UpdateComponents.ps1) | ⚠️ | Fully resets Windows Update: stops the services, clears SoftwareDistribution and catroot2, and re-registers the components. |
| [`Fix-UpdateError0x800f0922.ps1`](Update/Fix-UpdateError0x800f0922.ps1) | ⚠️ | Removes staged packages that block updates with error 0x800f0922. |
| [`Bypass-AllWin11RequirementsChecks.ps1`](Update/Bypass-AllWin11RequirementsChecks.ps1) | ⚠️ | Sets the registry values that bypass the Windows 11 TPM, Secure Boot, RAM, storage and CPU checks. **For lab and test use only.** |

### 🧰 Management, identity and miscellaneous

| Script | Type | Description |
|---|:---:|---|
| [`Install-RSATToolsActiveDirectory.ps1`](Management/Install-RSATToolsActiveDirectory.ps1) | 🛠️ | Installs the RSAT Active Directory tools if they are missing. |
| [`Get-ScheduledTaskReport.ps1`](Task%20Scheduler/Get-ScheduledTaskReport.ps1) | 🔍 | Exports detailed settings for every scheduled task to Excel. |
| [`Check-InstalledDotNet.ps1`](OSDependencies/Check-InstalledDotNet.ps1) | 🔍 | Lists the installed .NET Framework versions. |
| [`Reset-WindowsHello.ps1`](WindowsHello/Reset-WindowsHello.ps1) | ⚠️ | Resets the Windows Hello biometric database. Users must re-enroll. |
| [`Get-WiFiPassword4AllSavedSSIDs.ps1`](WiFi/Get-WiFiPassword4AllSavedSSIDs.ps1) | 🔍 | Recovers the saved Wi-Fi passphrases on the local machine. Handle the output as sensitive. |
| [`Set-ProcMonAltitude`](Set-ProcMonAltitude) | 🛠️ | Changes the Process Monitor driver altitude so it sees filter activity below other drivers. |

## Safety and usage guidelines

> [!WARNING]
> Many of these scripts change the registry, services, protocols or security policy. A wrong setting can break RDP, TLS connectivity, domain authentication or Windows Update.

1. **Read the script before you run it.** Check the referenced Microsoft KB or advisory linked in its header.
2. **Test in a lab or on a pilot group first**, especially the ⚠️ scripts. Schannel and RDP changes on domain controllers need particular care.
3. **Take a backup or snapshot.** At a minimum, export the affected registry keys (`reg export`). Some scripts, such as `Harden-SchannelSecurity-MS.ps1`, create backups themselves.
4. **Use `-WhatIf` and audit modes** where they exist. For example, run `Invoke-RDPHardening.ps1 -Mode Audit` or `Test-SchannelSecurity.ps1` before you remediate.
5. **Schedule a reboot.** Schannel, SMB, Spectre/Meltdown and IPv6 changes take effect only after a restart.

## Repository conventions

- **Naming:** `Verb-Noun.ps1` with [approved PowerShell verbs](https://learn.microsoft.com/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands).
- **Layout:** one folder per technology area (`Security`, `Network`, `RDP`, `WinGet`, …).
- **Help:** new scripts include comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.LINK`).
- **Safety:** scripts that make changes use `[CmdletBinding(SupportsShouldProcess)]` and `#Requires -RunAsAdministrator`.
- **Output:** reporting scripts return objects so you can pipe them to `Export-Csv`, `ConvertTo-Json` or `Export-Excel`.

## Roadmap

The repository is expanding with **services**, **processes**, **troubleshooting**, and **diagnostics and monitoring** toolsets, along with quality tooling (PSScriptAnalyzer, Pester, CI). See [ROADMAP.md](ROADMAP.md) for the full plan.

## Contributing

Issues and pull requests are welcome. When you contribute a script:

1. Follow the [repository conventions](#repository-conventions).
2. Run [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) with no errors: `Invoke-ScriptAnalyzer -Path .\YourScript.ps1`.
3. Say in the PR which Windows and PowerShell versions you tested on.
4. Add the script to the [catalog](#script-catalog) in this README.

## Disclaimer

These scripts are provided **"as is"**, without warranty of any kind. You are responsible for reviewing, testing and validating them before use in production. The author is not liable for any damage, data loss or service disruption they cause.
