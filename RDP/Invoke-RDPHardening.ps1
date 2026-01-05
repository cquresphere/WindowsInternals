<#
.SYNOPSIS
    Audit and (optionally) remediate RDP hardening settings with JSON/HTML reporting.

.DESCRIPTION
    - Audits RDP protocol settings (NLA, TLS, encryption level)
    - Audits TermService state
    - Optionally scopes Windows Firewall "Remote Desktop" inbound allow rules to approved remote addresses
    - Optionally enforces user rights for RDP logon (local security policy via secedit)
    - Optionally applies policy-backed RDS hardening
    - Produces production-friendly output: JSON (default), HTML report (optional), Table (optional)

.PARAMETER Mode
    Specifies the operation mode: Audit (default) or Remediate.

.PARAMETER AllowedRdpSources
    Array of IP addresses or CIDR ranges to restrict RDP access (e.g., "10.0.0.0/8", "203.0.113.10").

.PARAMETER EnforceUserRights
    Switch to enforce local user-rights assignments for RDP logon.

.PARAMETER ApplyRdsPolicyHardening
    Switch to apply policy-backed Terminal Services hardening settings.

.PARAMETER DisableRdpIfNotNeeded
    Switch to disable RDP when used with -Mode Remediate.

.PARAMETER OutputFormat
    Specifies output format: Json (default), Html, Table, or Both.

.PARAMETER HtmlReportPath
    Path for HTML report output. Defaults to current directory with timestamped filename.

.PARAMETER JsonOutPath
    Path for JSON output. If omitted, JSON is written to stdout.

.PARAMETER SkipGpupdate
    Skip running gpupdate after applying user rights changes.

.PARAMETER Force
    Force execution on Domain Controllers or when risky operations are detected.

.EXAMPLE
    .\Invoke-RDPHardening.ps1 -Mode Audit

    Performs an audit of RDP settings and outputs results in JSON format.

.EXAMPLE
    .\Invoke-RDPHardening.ps1 -Mode Audit -OutputFormat Html

    Performs an audit and generates an HTML report in the current directory.

.EXAMPLE
    .\Invoke-RDPHardening.ps1 -Mode Audit -OutputFormat Both -HtmlReportPath "C:\Reports\RDP-Audit.html"

    Audits RDP settings and outputs both JSON (to console) and HTML report to specified path.

.EXAMPLE
    .\Invoke-RDPHardening.ps1 -Mode Remediate -AllowedRdpSources "10.0.0.0/8","192.168.1.0/24" -WhatIf

    Shows what changes would be made to restrict RDP firewall rules to specific networks (without actually making changes).

.EXAMPLE
    .\Invoke-RDPHardening.ps1 -Mode Remediate -EnforceUserRights -ApplyRdsPolicyHardening -Confirm:$false

    Applies full RDP hardening including user rights and RDS policy settings without confirmation prompts.

.EXAMPLE
    .\Invoke-RDPHardening.ps1 -Mode Remediate -DisableRdpIfNotNeeded -Force

    Disables RDP on the system, including on Domain Controllers (requires -Force).

.NOTES
    Author: Karol Kula (cquresphere)
    Version: 2.0
    Requirements:
        - Run as Administrator
        - PowerShell 5.1 or later

    Important:
        - In domain environments, policy-backed keys under HKLM:\SOFTWARE\Policies may be overwritten by GPO/Intune.
        - Always validate changes in a staging OU/lab first.
        - Domain Controller remediation requires -Force parameter.

.LINK
    https://techcommunity.microsoft.com/blog/askds/more-speaking-in-ciphers-and-other-enigmatic-tongues-with-a-focus-on-schannel-ha/4047491
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
param(
    [ValidateSet("Audit","Remediate")]
    [string]$Mode = "Audit",

    # Restrict inbound RDP to these remote IPs/CIDRs (e.g. "10.0.0.0/8","203.0.113.10")
    [string[]]$AllowedRdpSources = @(),

    # Enforce local user-rights assignments (SeRemoteInteractiveLogonRight, SeDenyRemoteInteractiveLogonRight)
    [switch]$EnforceUserRights,

    # Apply policy-backed Terminal Services hardening (clipboard/drive redirection, timeouts, prompt)
    [switch]$ApplyRdsPolicyHardening,

    # If you truly want to disable RDP when not required, set with -Mode Remediate
    [switch]$DisableRdpIfNotNeeded,

    # Output format selection
    [ValidateSet("Json","Html","Table","Both")]
    [string]$OutputFormat = "Json",

    # Where to write HTML report (when OutputFormat includes Html). If not provided, writes to current dir.
    [string]$HtmlReportPath = $(Join-Path -Path (Get-Location) -ChildPath ("RdpHardeningReport_{0}_{1}.html" -f $env:COMPUTERNAME,(Get-Date).ToString("yyyyMMdd_HHmmss"))),

    # Where to write JSON output (optional). If omitted, JSON is written to pipeline/stdout.
    [string]$JsonOutPath = "",

    # Safety controls for risky operations
    [switch]$SkipGpupdate,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------------------------
# Helpers
# -------------------------

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsDomainController {
    try {
        $p = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions" -ErrorAction Stop
        return ($p.ProductType -eq "LanmanNT") # Domain Controller
    } catch {
        return $false
    }
}

function Get-RegDwordValue {
    param( [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name )
    if (Test-Path $Path) {
        try {
            $item = Get-ItemProperty -Path $Path -ErrorAction Stop
            if ($null -ne $item -and ($item.PSObject.Properties.Name -contains $Name)) {
                return [int]$item.$Name
            }
        } catch { 
            return $null
        }
    }
    return $null
}

function Set-RegDwordValue {
    param( [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][int]$Value )
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][ref]$Findings,
        [Parameter(Mandatory)][string]$Control,
        [Parameter(Mandatory)][string]$Setting,
        $Current,
        $Desired,
        [Parameter(Mandatory)][ValidateSet("PASS","FAIL","WARN","INFO")][string]$Status,
        [string]$RemediationHint = "",
        [string]$Evidence = ""
    )
    $Findings.Value += [pscustomobject]@{
        Control         = $Control
        Setting         = $Setting
        Status          = $Status
        Current         = $Current
        Desired         = $Desired
        RemediationHint = $RemediationHint
        Evidence        = $Evidence
    }
}

function Export-SecPolicy {
    param( [Parameter(Mandatory)][string]$OutPath )
    secedit /export /cfg $OutPath /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "secedit export failed with exit code $LASTEXITCODE" }
}

function Import-SecPolicy {
    param(
        [Parameter(Mandatory)][string]$InPath,
        [switch]$SkipGpupdate
    )
    $db = Join-Path $env:TEMP "rdp_hardening_secedit.sdb"
    secedit /configure /db $db /cfg $InPath /areas USER_RIGHTS /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "secedit configure failed with exit code $LASTEXITCODE" }

    if (-not $SkipGpupdate) {
        gpupdate /target:computer | Out-Null
    }

    # cleanup best-effort
    Remove-Item -Path $db -Force -ErrorAction SilentlyContinue
}

function Set-UserRightInInf {
    <#
        Updates a user right assignment line inside an exported security INF.
        The [Privilege Rights] section is ensured; the assignment is replaced or appended.

        IMPORTANT: Values should be *SIDs*; secedit supports name formats too, but SIDs are more deterministic.
    #>
    param(
        [Parameter(Mandatory)][string]$InfPath,
        [Parameter(Mandatory)][string]$RightName,
        [Parameter(Mandatory)][string[]]$SidList
    )

    $content = Get-Content -Path $InfPath -Encoding Unicode

    if (-not ($content -match '^\[Privilege Rights\]\s*$')) {
        $content += ""
        $content += "[Privilege Rights]"
    }

    $newLine = "$RightName = " + ($SidList -join ",")

    $inSection = $false
    $found = $false

    for ($i=0; $i -lt $content.Count; $i++) {
        if ($content[$i] -match '^\[Privilege Rights\]\s*$') { $inSection = $true; continue }
        if ($inSection -and $content[$i] -match '^\[') { break }

        if ($inSection -and $content[$i] -match ("^" + [regex]::Escape($RightName) + "\s*=")) {
            $content[$i] = $newLine
            $found = $true
            break
        }
    }

    if (-not $found) {
        # Insert right at end of section (before next section header, or at end)
        $out = New-Object System.Collections.Generic.List[string]
        $inSection = $false
        $inserted = $false

        for ($i=0; $i -lt $content.Count; $i++) {
            $line = $content[$i]
            if ($line -match '^\[Privilege Rights\]\s*$') { $inSection = $true }
            elseif ($inSection -and $line -match '^\[') {
                if (-not $inserted) { $out.Add($newLine); $inserted = $true }
                $inSection = $false
            }

            $out.Add($line)
        }

        if (-not $inserted) { $out.Add($newLine) }
        $content = $out.ToArray()
    }

    Set-Content -Path $InfPath -Value $content -Encoding Unicode
}

function Get-RdpFirewallAllowRules {
    <#
        Returns enabled inbound allow rules in the "Remote Desktop" display group.
        Filters to rules that can actually allow inbound traffic.
    #>
    try {
        $rules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop |
        Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" }
        return @($rules)
    } catch {
        return @()
    }
}

function Get-FirewallRemoteAddresses {
    param( [Parameter(Mandatory)]$Rule )
    try {
        $filters = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
        $addrs = @()
        foreach ($f in @($filters)) {
            if ($null -ne $f.RemoteAddress) { $addrs += @($f.RemoteAddress) }
        }
        # Normalize to strings, flatten
        $addrs = $addrs | ForEach-Object { $_.ToString() } | Where-Object { $_ -and $_.Trim() -ne "" }
        if ($addrs.Count -eq 0) { return @("Any") }
        return $addrs
    } catch {
        return @("Unknown")
    }
}

function Test-AllRulesScoped {
    param( [Parameter(Mandatory)]$Rules )
    $rulesList = @($Rules)
    if ($rulesList.Count -eq 0) { return $false }

    foreach ($r in $rulesList) {
        $addrs = Get-FirewallRemoteAddresses -Rule $r
        # Consider unscoped if Any is present, or unknown
        if ($addrs -contains "Any" -or $addrs -contains "Unknown") { return $false }
    }
    return $true
}

function New-HtmlReport {
    param(
        [Parameter(Mandatory)][pscustomobject]$Structured,
        [Parameter(Mandatory)][string]$OutPath
    )

    $findings = $Structured.Findings
    $counts = $findings | Group-Object Status | ForEach-Object {
        [pscustomobject]@{ Status = $_.Name; Count = $_.Count }
    }
    $pass = ($counts | Where-Object Status -eq "PASS" | Select-Object -ExpandProperty Count -ErrorAction SilentlyContinue)
    $fail = ($counts | Where-Object Status -eq "FAIL" | Select-Object -ExpandProperty Count -ErrorAction SilentlyContinue)
    $warn = ($counts | Where-Object Status -eq "WARN" | Select-Object -ExpandProperty Count -ErrorAction SilentlyContinue)
    $info = ($counts | Where-Object Status -eq "INFO" | Select-Object -ExpandProperty Count -ErrorAction SilentlyContinue)
    if ($null -eq $pass) { $pass = 0 }
    if ($null -eq $fail) { $fail = 0 }
    if ($null -eq $warn) { $warn = 0 }
    if ($null -eq $info) { $info = 0 }

    $metaRows = @(
        [pscustomobject]@{ Key="ComputerName"; Value=$Structured.ComputerName },
        [pscustomobject]@{ Key="Timestamp";    Value=$Structured.Timestamp },
        [pscustomobject]@{ Key="Mode";         Value=$Structured.Mode },
        [pscustomobject]@{ Key="Notes";        Value=$Structured.Notes }
    )

    $metaHtml = $metaRows | ConvertTo-Html -Fragment -Property Key,Value

        # Encode text for safe HTML insertion
        function HtmlEncode([string]$s) {
            if ($null -eq $s) { return "" }
            return [System.Net.WebUtility]::HtmlEncode($s)
        }

    $rows = foreach ($f in $findings) {
        [pscustomobject]@{
        Status  = $f.Status
        Control = $f.Control
        Setting = $f.Setting
        Current = $f.Current
        Desired = $f.Desired
        Hint    = $f.RemediationHint
        Evidence= $f.Evidence
        }
    }

    $tableHtml = $rows | ConvertTo-Html -Fragment -Property Status,Control,Setting,Current,Desired,Hint,Evidence

    $html = @"
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>RDP Hardening Report - $(HtmlEncode($Structured.ComputerName))</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #111; }
    h1 { margin-bottom: 6px; }
    .sub { color: #555; margin-top: 0; }
    .cards { display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0 20px; }
    .card { border: 1px solid #ddd; border-radius: 10px; padding: 12px 14px; min-width: 150px; }
    .card .k { color: #666; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
    .card .v { font-size: 28px; margin-top: 4px; }
    .card.pass { background: #f3fff3; border-color: #b8e6b8; }
    .card.fail { background: #fff3f3; border-color: #e6b8b8; }
    .card.warn { background: #fffdf0; border-color: #e6e0a8; }
    .card.info { background: #f3f7ff; border-color: #b8d4e6; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px 10px; vertical-align: top; }
    th { background: #f6f6f6; position: sticky; top: 0; z-index: 1; }
    tr.pass td { background: #f3fff3; }
    tr.fail td { background: #fff3f3; }
    tr.warn td { background: #fffdf0; }
    tr.info td { background: #f3f7ff; }
    .filters { display: flex; gap: 8px; margin: 10px 0 14px; flex-wrap: wrap; }
    .filters button { border: 1px solid #ccc; background: #fff; padding: 6px 10px; border-radius: 8px; cursor: pointer; }
    .filters button.active { border-color: #111; }
    .meta { margin: 10px 0 16px; }
    .foot { margin-top: 18px; color: #666; font-size: 12px; }
    .mono { font-family: Consolas, monospace; }
  </style>
</head>
<body>
  <h1>RDP Hardening Report</h1>
  <p class="sub">Computer: <span class="mono">$(HtmlEncode($Structured.ComputerName))</span> — Generated: <span class="mono">$(HtmlEncode($Structured.Timestamp))</span></p>

  <div class="cards">
    <div class="card pass"><div class="k">PASS</div><div class="v">$pass</div></div>
    <div class="card fail"><div class="k">FAIL</div><div class="v">$fail</div></div>
    <div class="card warn"><div class="k">WARN</div><div class="v">$warn</div></div>
    <div class="card info"><div class="k">INFO</div><div class="v">$info</div></div>
  </div>

  <h2>Run Metadata</h2>
  <div class="meta">
    $metaHtml
  </div>

  <h2>Findings</h2>
  <div class="filters">
    <button onclick="setFilter('ALL')" id="btnALL" class="active">All</button>
    <button onclick="setFilter('FAIL')" id="btnFAIL">Fail</button>
    <button onclick="setFilter('WARN')" id="btnWARN">Warn</button>
    <button onclick="setFilter('PASS')" id="btnPASS">Pass</button>
    <button onclick="setFilter('INFO')" id="btnINFO">Info</button>
  </div>

  <div id="findingsTable">
    $tableHtml
  </div>

  <div class="foot">
    Notes: Settings under HKLM:\SOFTWARE\Policies may be governed by domain policy and can be overwritten.
  </div>

<script>
  function setFilter(status) {
    const buttons = ['ALL','FAIL','WARN','PASS','INFO'];
    buttons.forEach(s => document.getElementById('btn'+s).classList.remove('active'));
    document.getElementById('btn'+status).classList.add('active');

    const rows = document.querySelectorAll('#findingsTable table tbody tr');
    rows.forEach(r => {
      const cell = r.querySelector('td');
      if (!cell) return;
      const s = cell.textContent.trim().toUpperCase();
      if (status === 'ALL' || s === status) r.style.display = '';
      else r.style.display = 'none';
    });
  }

  // Add row classes for styling
  (function() {
    const rows = document.querySelectorAll('#findingsTable table tbody tr');
    rows.forEach(r => {
      const s = (r.querySelector('td') || {}).textContent || '';
      const t = s.trim().toLowerCase();
      if (t) r.classList.add(t);
    });
  })();
</script>
</body>
</html>
"@

    $dir = Split-Path -Path $OutPath -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -Path $OutPath -Value $html -Encoding UTF8
}

# -------------------------
# Safety checks
# -------------------------
if (-not (Test-IsAdmin)) {
    throw "This script must be run as Administrator."
}

$IsDC = Test-IsDomainController
if ($IsDC -and $Mode -eq "Remediate" -and -not $Force) {
    throw "This host appears to be a Domain Controller. Remediation is blocked unless -Force is specified."
}

# -------------------------
# Desired profile (safe defaults; customize as needed)
# -------------------------
$Desired = [pscustomobject]@{
    # Core RDP protocol posture
    RdpEnabled           = 1      # 1 = enabled (fDenyTSConnections=0); 0 = disabled (fDenyTSConnections=1)
    NlaRequired          = 1      # UserAuthentication = 1
    SecurityLayer        = 2      # 2 = TLS
    MinEncryptionLevel   = 3      # 3 = High (128-bit); 4 = FIPS (environment-specific)

    # Policy-backed hardening (optional)
    PromptForPassword    = 1
    EncryptRpcTraffic    = 1
    DisableClipboard     = 1
    DisableDriveRedir    = 1
    MaxIdleTimeMs        = 15*60*1000
    MaxDisconnectionMs   = 60*60*1000
    ResetBroken          = 1
    SingleSessionPerUser = 1

    # User rights defaults (can be adjusted below)
    AllowRdpLogonSids    = @("S-1-5-32-544","S-1-5-32-555") # Administrators, Remote Desktop Users
    DenyRdpLogonSids     = @("S-1-5-32-546","S-1-5-113")   # Guests, Local account (be careful in break-glass scenarios)
}

if ($DisableRdpIfNotNeeded) {
    $Desired.RdpEnabled = 0
}

# -------------------------
# Audit logic
# -------------------------
$Findings = @()

$tsControlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$rdpTcpPath    = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$policyTsPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# RDP enabled?
$currentDeny = Get-RegDwordValue -Path $tsControlPath -Name "fDenyTSConnections"
$currentRdpEnabled = if ($null -eq $currentDeny) { $null } elseif ($currentDeny -eq 0) { 1 } else { 0 }

$rdpStatus = if ($null -eq $currentRdpEnabled) { "WARN" } elseif ($currentRdpEnabled -eq $Desired.RdpEnabled) { "PASS" } else { "FAIL" }
Add-Finding -Findings ([ref]$Findings) -Control "MS/CIS-RDP-01" -Setting "RDP Enabled" `
    -Current $currentRdpEnabled -Desired $Desired.RdpEnabled -Status $rdpStatus `
    -RemediationHint "Set fDenyTSConnections (0=enable, 1=disable). Disable if not required." `
    -Evidence "HKLM:\...\Terminal Server\fDenyTSConnections"

# NLA required?
$currentNla = Get-RegDwordValue -Path $rdpTcpPath -Name "UserAuthentication"
$nlaStatus = if ($null -eq $currentNla) { "WARN" } elseif ($currentNla -eq $Desired.NlaRequired) { "PASS" } else { "FAIL" }
Add-Finding -Findings ([ref]$Findings) -Control "MS/CIS-RDP-02" -Setting "Require NLA (UserAuthentication)" `
    -Current $currentNla -Desired $Desired.NlaRequired -Status $nlaStatus `
    -RemediationHint "Set UserAuthentication=1 to require NLA." `
    -Evidence "HKLM:\...\RDP-Tcp\UserAuthentication"

# Security layer (TLS)
$currentSecLayer = Get-RegDwordValue -Path $rdpTcpPath -Name "SecurityLayer"
$secStatus = if ($null -eq $currentSecLayer) { "WARN" } elseif ($currentSecLayer -eq $Desired.SecurityLayer) { "PASS" } else { "FAIL" }
Add-Finding -Findings ([ref]$Findings) -Control "MS/CIS-RDP-03" -Setting "RDP Security Layer (TLS) (SecurityLayer)" `
    -Current $currentSecLayer -Desired $Desired.SecurityLayer -Status $secStatus `
    -RemediationHint "Set SecurityLayer=2 to require TLS." `
    -Evidence "HKLM:\...\RDP-Tcp\SecurityLayer"

# Minimum encryption
$currentMinEnc = Get-RegDwordValue -Path $rdpTcpPath -Name "MinEncryptionLevel"
$minEncStatus = if ($null -eq $currentMinEnc) { "WARN" } elseif ($currentMinEnc -ge $Desired.MinEncryptionLevel) { "PASS" } else { "FAIL" }
Add-Finding -Findings ([ref]$Findings) -Control "MS/CIS-RDP-04" -Setting "RDP Min Encryption (MinEncryptionLevel)" `
    -Current $currentMinEnc -Desired (">= " + $Desired.MinEncryptionLevel) -Status $minEncStatus `
    -RemediationHint "Set MinEncryptionLevel to 3 (High/128-bit) or 4 (FIPS) per policy." `
    -Evidence "HKLM:\...\RDP-Tcp\MinEncryptionLevel"

# TermService service state
$svc = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Add-Finding -Findings ([ref]$Findings) -Control "MS/CIS-RDP-05" -Setting "TermService present" `
        -Current "Not found" -Desired "Present" -Status "WARN" `
        -RemediationHint "RDP host service not installed or not applicable." `
        -Evidence "Get-Service TermService"
} else {
    $desiredSvc = if ($Desired.RdpEnabled -eq 1) { "Running" } else { "Not required (RDP disabled)" }
    $svcStatus = if ($Desired.RdpEnabled -eq 1 -and $svc.Status -eq "Running") { "PASS" }
        elseif ($Desired.RdpEnabled -eq 0) { "INFO" }
        else { "WARN" }

    Add-Finding -Findings ([ref]$Findings) -Control "MS/CIS-RDP-05" -Setting "TermService status" `
        -Current $svc.Status -Desired $desiredSvc -Status $svcStatus `
        -RemediationHint "If RDP is required, ensure TermService is running." `
        -Evidence "Get-Service TermService"
}

# Firewall scoping (strict): PASS only if ALL enabled inbound allow RDP rules are scoped (no Any)
$rdpRules = @(Get-RdpFirewallAllowRules)
if ($rdpRules.Count -eq 0) {
    Add-Finding -Findings ([ref]$Findings) -Control "MS/CIS-RDP-06" -Setting "Firewall inbound allow rules (Remote Desktop group)" `
        -Current "None found or not queryable" -Desired "Queryable rules" -Status "WARN" `
        -RemediationHint "Ensure the 'Remote Desktop' firewall group exists or validate custom rules for TCP/3389." `
        -Evidence "Get-NetFirewallRule -DisplayGroup 'Remote Desktop'"
} else {
    $allScoped = Test-AllRulesScoped -Rules $rdpRules
    $currentScope = if ($allScoped) { "Scoped (all inbound allow rules)" } else { "Unscoped (at least one allows Any/Unknown)" }

    $fwStatus = if ($AllowedRdpSources.Count -gt 0 -and $allScoped) { "PASS" }
        elseif ($AllowedRdpSources.Count -gt 0 -and -not $allScoped) { "FAIL" }
        else { "WARN" }

    $evidence = ($rdpRules | ForEach-Object {
        $addrs = (Get-FirewallRemoteAddresses -Rule $_) -join ";"
        "{0} => {1}" -f $_.Name, $addrs
    }) -join " | "

    Add-Finding -Findings ([ref]$Findings) -Control "MS/CIS-RDP-06" -Setting "Firewall RDP rules remote scope" `
        -Current $currentScope -Desired "Scoped to approved sources" -Status $fwStatus `
        -RemediationHint "Use -AllowedRdpSources to restrict RDP to VPN/bastion/RD Gateway networks." `
        -Evidence $evidence
}

# Policy governance hint
$policyHint = if (Test-Path $policyTsPath) { "Policy path exists; settings may be governed by GPO/Intune and overwritten." } else { "Policy path not present; local policy hardening may apply if set." }
Add-Finding -Findings ([ref]$Findings) -Control "OPS-GOV-01" -Setting "Policy governance (HKLM:\SOFTWARE\Policies...)" `
    -Current $policyHint -Desired "Operator awareness" -Status "INFO" `
    -RemediationHint "If settings revert, check domain GPO/Intune baselines." `
    -Evidence $policyTsPath

# -------------------------
# Remediation (optional)
# -------------------------
if ($Mode -eq "Remediate") {

    if ($IsDC -and -not $Force) {
        throw "Domain Controller remediation requires -Force."
    }

    # Guard: disabling local accounts for RDP can remove break-glass access. Require -Force if deny includes Local account.
    if ($EnforceUserRights -and ($Desired.DenyRdpLogonSids -contains "S-1-5-113") -and -not $Force) {
        throw "Deny list includes S-1-5-113 (Local account). This can break the break-glass access. Use -Force to proceed."
    }

    # Apply changes in granular ShouldProcess blocks
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Set core RDP registry posture")) {
        $targetDeny = if ($Desired.RdpEnabled -eq 1) { 0 } else { 1 }
        Set-RegDwordValue -Path $tsControlPath -Name "fDenyTSConnections" -Value $targetDeny
        Set-RegDwordValue -Path $rdpTcpPath -Name "UserAuthentication"   -Value $Desired.NlaRequired
        Set-RegDwordValue -Path $rdpTcpPath -Name "SecurityLayer"        -Value $Desired.SecurityLayer
        Set-RegDwordValue -Path $rdpTcpPath -Name "MinEncryptionLevel"   -Value $Desired.MinEncryptionLevel
    }

    if ($ApplyRdsPolicyHardening -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Apply policy-backed RDS hardening registry keys")) {
        Set-RegDwordValue -Path $policyTsPath -Name "fPromptForPassword"          -Value $Desired.PromptForPassword
        Set-RegDwordValue -Path $policyTsPath -Name "fEncryptRPCTraffic"          -Value $Desired.EncryptRpcTraffic
        Set-RegDwordValue -Path $policyTsPath -Name "fDisableClip"                -Value $Desired.DisableClipboard
        Set-RegDwordValue -Path $policyTsPath -Name "fDisableClipboardRedirection"-Value $Desired.DisableClipboard
        Set-RegDwordValue -Path $policyTsPath -Name "fDisableCdm"                 -Value $Desired.DisableDriveRedir
        Set-RegDwordValue -Path $policyTsPath -Name "MaxIdleTime"                 -Value $Desired.MaxIdleTimeMs
        Set-RegDwordValue -Path $policyTsPath -Name "MaxDisconnectionTime"        -Value $Desired.MaxDisconnectionMs
        Set-RegDwordValue -Path $policyTsPath -Name "fResetBroken"                -Value $Desired.ResetBroken
        Set-RegDwordValue -Path $policyTsPath -Name "fSingleSessionPerUser"       -Value $Desired.SingleSessionPerUser
    }

    if ($AllowedRdpSources.Count -gt 0 -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Scope inbound Remote Desktop firewall allow rules")) {
        $rules = Get-RdpFirewallAllowRules
        foreach ($r in $rules) {
            # Ensure enabled and set remote scope
            Set-NetFirewallRule -Name $r.Name -Enabled True | Out-Null
            Set-NetFirewallRule -Name $r.Name -RemoteAddress $AllowedRdpSources | Out-Null
        }
    }

    if ($EnforceUserRights -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Enforce local user-rights assignments via secedit")) {
        $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $infBackup = Join-Path $env:TEMP "rdp_user_rights_export_$stamp.inf"
        $infWork   = Join-Path $env:TEMP "rdp_user_rights_work_$stamp.inf"

        Export-SecPolicy -OutPath $infBackup
        Copy-Item -Path $infBackup -Destination $infWork -Force

        Set-UserRightInInf -InfPath $infWork -RightName "SeRemoteInteractiveLogonRight"     -SidList $Desired.AllowRdpLogonSids
        Set-UserRightInInf -InfPath $infWork -RightName "SeDenyRemoteInteractiveLogonRight" -SidList $Desired.DenyRdpLogonSids

        Import-SecPolicy -InPath $infWork -SkipGpupdate:$SkipGpupdate

        # Best-effort cleanup of work file; keep backup for rollback
        Remove-Item $infWork -Force -ErrorAction SilentlyContinue
    }
    # Service handling:
    # Only adjust service automatically when explicitly disabling RDP (to avoid breaking RDS deployments).
    $svc = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
    if ($svc -and $Desired.RdpEnabled -eq 0 -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Disable TermService because RDP is disabled")) {
        Stop-Service -Name "TermService" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "TermService" -StartupType Disabled
    }
}

# -------------------------
# Re-audit after remediation for accurate report
# -------------------------
# Lightweight re-audit of the same set of checks
function Invoke-AuditSnapshot {
    param( [pscustomobject]$Desired )

    $snap = @()

    $tsControlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $rdpTcpPath    = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    $policyTsPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

    $currentDeny = Get-RegDwordValue -Path $tsControlPath -Name "fDenyTSConnections"
    $currentRdpEnabled = if ($null -eq $currentDeny) { $null } elseif ($currentDeny -eq 0) { 1 } else { 0 }
    $rdpStatus = if ($null -eq $currentRdpEnabled) { "WARN" } elseif ($currentRdpEnabled -eq $Desired.RdpEnabled) { "PASS" } else { "FAIL" }
    Add-Finding -Findings ([ref]$snap) -Control "MS/CIS-RDP-01" -Setting "RDP Enabled" -Current $currentRdpEnabled -Desired $Desired.RdpEnabled -Status $rdpStatus

    $currentNla = Get-RegDwordValue -Path $rdpTcpPath -Name "UserAuthentication"
    $nlaStatus = if ($null -eq $currentNla) { "WARN" } elseif ($currentNla -eq $Desired.NlaRequired) { "PASS" } else { "FAIL" }
    Add-Finding -Findings ([ref]$snap) -Control "MS/CIS-RDP-02" -Setting "Require NLA (UserAuthentication)" -Current $currentNla -Desired $Desired.NlaRequired -Status $nlaStatus

    $currentSecLayer = Get-RegDwordValue -Path $rdpTcpPath -Name "SecurityLayer"
    $secStatus = if ($null -eq $currentSecLayer) { "WARN" } elseif ($currentSecLayer -eq $Desired.SecurityLayer) { "PASS" } else { "FAIL" }
    Add-Finding -Findings ([ref]$snap) -Control "MS/CIS-RDP-03" -Setting "RDP Security Layer (TLS) (SecurityLayer)" -Current $currentSecLayer -Desired $Desired.SecurityLayer -Status $secStatus

    $currentMinEnc = Get-RegDwordValue -Path $rdpTcpPath -Name "MinEncryptionLevel"
    $minEncStatus = if ($null -eq $currentMinEnc) { "WARN" } elseif ($currentMinEnc -ge $Desired.MinEncryptionLevel) { "PASS" } else { "FAIL" }
    Add-Finding -Findings ([ref]$snap) -Control "MS/CIS-RDP-04" -Setting "RDP Min Encryption (MinEncryptionLevel)" -Current $currentMinEnc -Desired (">= " + $Desired.MinEncryptionLevel) -Status $minEncStatus

    $svc = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Add-Finding -Findings ([ref]$snap) -Control "MS/CIS-RDP-05" -Setting "TermService present" -Current "Not found" -Desired "Present" -Status "WARN"
    } else {
        $svcStatus = if ($Desired.RdpEnabled -eq 1 -and $svc.Status -eq "Running") { "PASS" }
            elseif ($Desired.RdpEnabled -eq 0) { "INFO" }
            else { "WARN" }
        $desiredSvcState = if ($Desired.RdpEnabled -eq 1) {"Running"} else {"Not required"}
        Add-Finding -Findings ([ref]$snap) -Control "MS/CIS-RDP-05" -Setting "TermService status" -Current $svc.Status -Desired $desiredSvcState -Status $svcStatus
    }

    $rules = @(Get-RdpFirewallAllowRules)
    if ($rules.Count -eq 0) {
        Add-Finding -Findings ([ref]$snap) -Control "MS/CIS-RDP-06" -Setting "Firewall inbound allow rules (Remote Desktop group)" -Current "None found or not queryable" -Desired "Queryable rules" -Status "WARN"
    } else {
        $allScoped = Test-AllRulesScoped -Rules $rules
        $currentScope = if ($allScoped) { "Scoped (all inbound allow rules)" } else { "Unscoped (at least one allows Any/Unknown)" }
        $fwStatus = if ($AllowedRdpSources.Count -gt 0 -and $allScoped) { "PASS" }
                    elseif ($AllowedRdpSources.Count -gt 0 -and -not $allScoped) { "FAIL" }
                    else { "WARN" }
        Add-Finding -Findings ([ref]$snap) -Control "MS/CIS-RDP-06" -Setting "Firewall RDP rules remote scope" -Current $currentScope -Desired "Scoped to approved sources" -Status $fwStatus
    }

    $policyHint = if (Test-Path $policyTsPath) { "Policy path exists; settings may be governed and overwritten." } else { "Policy path not present." }
    Add-Finding -Findings ([ref]$snap) -Control "OPS-GOV-01" -Setting "Policy governance (HKLM:\SOFTWARE\Policies...)" -Current $policyHint -Desired "Operator awareness" -Status "INFO"

    return $snap
}

$FinalFindings = Invoke-AuditSnapshot -Desired $Desired

# -------------------------
# Output
# -------------------------
$structured = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = (Get-Date).ToString("s")
    Mode         = $Mode
    Notes        = @(
        if ($IsDC) { "Host appears to be a Domain Controller." } else { "Host appears to be a member server/workstation." }
        if ($AllowedRdpSources.Count -gt 0) { "Firewall scoping requested." } else { "No firewall scoping requested (audit will WARN)." }
        if ($ApplyRdsPolicyHardening) { "Policy-backed RDS hardening requested." } else { "Policy-backed RDS hardening not requested." }
        if ($EnforceUserRights) { "User-rights enforcement requested." } else { "User-rights enforcement not requested." }
        if ($SkipGpupdate) { "gpupdate skipped by request." } else { "gpupdate may run if user-rights are enforced." }
    ) -join " "
    Findings     = $FinalFindings
}

# Table output (operator-friendly, not ideal for automation)
if ($OutputFormat -in @("Table","Both")) {
    $structured.Findings | Sort-Object Status, Control | Format-Table -AutoSize
}

# JSON output
$json = $structured | ConvertTo-Json -Depth 8
if ($OutputFormat -in @("Json","Both")) {
    if ([string]::IsNullOrWhiteSpace($JsonOutPath)) {
        $json
    } else {
        $dir = Split-Path -Path $JsonOutPath -Parent
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Set-Content -Path $JsonOutPath -Value $json -Encoding UTF8
        Write-Verbose "Wrote JSON to $JsonOutPath"
    }
}

# HTML output
if ($OutputFormat -in @("Html","Both")) {
    New-HtmlReport -Structured $structured -OutPath $HtmlReportPath
    Write-Output "HTML report written to: $HtmlReportPath"
}
