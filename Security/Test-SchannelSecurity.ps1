<#
.SYNOPSIS
    Audit Windows Schannel TLS/SSL Security Configuration
    Non-invasive scan - makes no changes, only reports the current state.

.DESCRIPTION
    Comprehensive security audit that checks:
    - Protocol status (SSL 2.0/3.0, TLS 1.0/1.1/1.2/1.3)
    - Cipher configuration
    - Hash algorithm status
    - Key exchange settings
    - Cipher suite order
    - .NET Framework TLS settings
    - WinHTTP settings
    - Compliance against 2026+ security standards

.PARAMETER OutputFormat
    Output format: Console, HTML, JSON, or All. Default: Console

.PARAMETER OutputPath
    Directory for report files. Default: $env:TEMP

.EXAMPLE
    .\Test-SchannelSecurity.ps1
    Run audit with console output.

.EXAMPLE
    .\Test-SchannelSecurity.ps1 -OutputFormat HTML -OutputPath "C:\Reports"
    Generate an HTML report in the specified directory.

.EXAMPLE
    .\Test-SchannelSecurity.ps1 -OutputFormat All
    Generate all output formats (Console, HTML, JSON).

.NOTES
    Author:         Karol Kula (cquresphere) 
    Version:        2.0.1
    Last Updated:   02.01.2026
#>

[CmdletBinding()]
param(
    [ValidateSet('Console', 'HTML', 'JSON', 'All')]
    [string]$OutputFormat = 'Console',
    
    [string]$OutputPath = $env:TEMP
)

#region Configuration
$Script:SchannelBasePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
$Script:Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# 2026+ Security Requirements
$Script:Requirements = @{
    Protocols = @{
        'SSL 2.0' = @{ Required = 'Disabled'; Severity = 'Critical' }
        'SSL 3.0' = @{ Required = 'Disabled'; Severity = 'Critical' }
        'TLS 1.0' = @{ Required = 'Disabled'; Severity = 'High' }
        'TLS 1.1' = @{ Required = 'Disabled'; Severity = 'Medium' }
        'TLS 1.2' = @{ Required = 'Enabled';  Severity = 'Critical' }
        'TLS 1.3' = @{ Required = 'Enabled';  Severity = 'High' }
    }
    MinDhKeyBits = 2048
    RecommendedDhKeyBits = 3072
    WeakCiphers = @('NULL', 'DES', 'RC2', 'RC4', '3DES', 'Triple DES')
    WeakHashes = @('MD5')
    WeakCipherSuitePatterns = @('*RC4*', '*RC2*', '*DES*', '*NULL*', '*EXPORT*', '*anon*', '*MD5*')
}
#endregion

#region Helper Functions
function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        return (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).$Name
    } catch { return $null }
}

function Get-ProtocolStatus {
    param([string]$Protocol)
    
    $result = @{
        Protocol = $Protocol
        ServerEnabled = $null
        ServerDisabledByDefault = $null
        ClientEnabled = $null
        ClientDisabledByDefault = $null
        EffectiveServer = 'Unknown'
        EffectiveClient = 'Unknown'
        Compliant = $false
        Severity = $Script:Requirements.Protocols[$Protocol].Severity
        Required = $Script:Requirements.Protocols[$Protocol].Required
    }
    
    $basePath = "$Script:SchannelBasePath\Protocols\$Protocol"
    
    # Server
    $result.ServerEnabled = Get-RegistryValue -Path "$basePath\Server" -Name 'Enabled'
    $result.ServerDisabledByDefault = Get-RegistryValue -Path "$basePath\Server" -Name 'DisabledByDefault'
    
    # Client
    $result.ClientEnabled = Get-RegistryValue -Path "$basePath\Client" -Name 'Enabled'
    $result.ClientDisabledByDefault = Get-RegistryValue -Path "$basePath\Client" -Name 'DisabledByDefault'
    
    # Determine effective state
    $result.EffectiveServer = if ($result.ServerEnabled -eq 0) { 'Disabled' }
                              elseif ($result.ServerEnabled -eq 1) { 'Enabled' }
                              elseif ($result.ServerDisabledByDefault -eq 1) { 'Disabled (Default)' }
                              else { 'Enabled (OS Default)' }
    
    $result.EffectiveClient = if ($result.ClientEnabled -eq 0) { 'Disabled' }
                              elseif ($result.ClientEnabled -eq 1) { 'Enabled' }
                              elseif ($result.ClientDisabledByDefault -eq 1) { 'Disabled (Default)' }
                              else { 'Enabled (OS Default)' }
    
    # Check compliance
    $serverOk = ($result.Required -eq 'Disabled' -and $result.EffectiveServer -like 'Disabled*') -or
                ($result.Required -eq 'Enabled' -and $result.EffectiveServer -like 'Enabled*')
    $clientOk = ($result.Required -eq 'Disabled' -and $result.EffectiveClient -like 'Disabled*') -or
                ($result.Required -eq 'Enabled' -and $result.EffectiveClient -like 'Enabled*')
    
    $result.Compliant = $serverOk -and $clientOk
    
    return [PSCustomObject]$result
}

function Get-CipherStatus {
    param([string]$CipherName)
    
    # Use .NET Registry class to handle cipher names with "/" correctly
    # PowerShell's path handling interprets "/" as a path separator
    $regPath = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$CipherName"
    $enabled = $null
    
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regPath)
        if ($null -ne $key) {
            $enabled = $key.GetValue('Enabled', $null)
            $key.Close()
        }
    } catch {
        $enabled = $null
    }
    
    $isWeak = $Script:Requirements.WeakCiphers | Where-Object { $CipherName -like "*$_*" }
    
    # Determine if cipher is disabled (value 0) - cast to int for reliable comparison
    $isDisabled = ($null -ne $enabled) -and ([int]$enabled -eq 0)
    
    return [PSCustomObject]@{
        Cipher = $CipherName
        Enabled = if ($null -eq $enabled) { 'Not Set (OS Default)' } elseif ($enabled -eq 1) { 'Enabled' } else { 'Disabled' }
        IsWeak = [bool]$isWeak
        Compliant = if ($isWeak) { $isDisabled } else { $true }
        Severity = if ($isWeak) { 'High' } else { 'Info' }
    }
}

function Get-HashStatus {
    param([string]$HashName)
    
    $path = "$Script:SchannelBasePath\Hashes\$HashName"
    $enabled = Get-RegistryValue -Path $path -Name 'Enabled'
    
    # MD5 is weak and should be disabled
    # SHA (SHA1) - per Microsoft should be ENABLED (0xFFFFFFFF) for RDP compatibility
    $isWeak = $HashName -eq 'MD5'
    
    # Special handling for SHA: it's legacy but REQUIRED for RDP certificates
    $isSha1 = $HashName -eq 'SHA'
    
    return [PSCustomObject]@{
        Hash = $HashName
        Enabled = if ($null -eq $enabled) { 'Not Set (OS Default)' } 
                  elseif ($enabled -eq 0xFFFFFFFF -or $enabled -eq 1) { 'Enabled' } 
                  elseif ($enabled -eq 0) { 'Disabled' }
                  else { "Enabled ($enabled)" }
        IsWeak = $isWeak
        # SHA compliance: should be enabled per Microsoft for RDP
        # MD5 compliance: should be disabled
        Compliant = if ($isWeak) { $enabled -eq 0 } 
                    elseif ($isSha1) { $enabled -ne 0 -or $null -eq $enabled }  # SHA should NOT be disabled
                    else { $true }
        Severity = if ($HashName -eq 'MD5') { 'High' } elseif ($HashName -eq 'SHA') { 'Info' } else { 'Info' }
    }
}

function Get-KeyExchangeStatus {
    $keyExPath = "$Script:SchannelBasePath\KeyExchangeAlgorithms"
    
    $dhPath = "$keyExPath\Diffie-Hellman"
    $serverMinKey = Get-RegistryValue -Path $dhPath -Name 'ServerMinKeyBitLength'
    $clientMinKey = Get-RegistryValue -Path $dhPath -Name 'ClientMinKeyBitLength'
    $dhEnabled = Get-RegistryValue -Path $dhPath -Name 'Enabled'
    
    $ecdhEnabled = Get-RegistryValue -Path "$keyExPath\ECDH" -Name 'Enabled'
    $pkcsEnabled = Get-RegistryValue -Path "$keyExPath\PKCS" -Name 'Enabled'
    
    $minKey = [Math]::Min(
        $(if ($serverMinKey) { $serverMinKey } else { 1024 }),
        $(if ($clientMinKey) { $clientMinKey } else { 1024 })
    )
    
    # Helper function to determine if algorithm is enabled
    # Values: 0 = Disabled, 1 = Enabled, 0xFFFFFFFF = Enabled, $null = OS Default (usually enabled)
    function Test-AlgorithmEnabled($value) {
        if ($null -eq $value) { return $null }  # Not set
        if ($value -eq 0) { return $false }      # Explicitly disabled
        return $true                              # Any non-zero value means enabled (1 or 0xFFFFFFFF)
    }
    
    function Get-AlgorithmDisplayStatus($value) {
        if ($null -eq $value) { return 'Not Set (OS Default: Enabled)' }
        if ($value -eq 0) { return 'Disabled' }
        if ($value -eq 1) { return 'Enabled' }
        if ($value -eq 0xFFFFFFFF -or $value -eq -1) { return 'Enabled (0xFFFFFFFF)' }
        return "Enabled ($value)"
    }
    
    return [PSCustomObject]@{
        DiffieHellman = @{
            Enabled = Get-AlgorithmDisplayStatus $dhEnabled
            ServerMinKeyBits = if ($serverMinKey) { $serverMinKey } else { 'Not Set (OS Default ~1024)' }
            ClientMinKeyBits = if ($clientMinKey) { $clientMinKey } else { 'Not Set (OS Default ~1024)' }
            EffectiveMinBits = $minKey
            Compliant = $minKey -ge $Script:Requirements.MinDhKeyBits
            MeetsRecommended = $minKey -ge $Script:Requirements.RecommendedDhKeyBits
        }
        ECDH = @{
            Enabled = Get-AlgorithmDisplayStatus $ecdhEnabled
            Compliant = (Test-AlgorithmEnabled $ecdhEnabled) -ne $false  # Compliant if enabled or not set
        }
        PKCS = @{
            Enabled = Get-AlgorithmDisplayStatus $pkcsEnabled
        }
    }
}

function Get-CipherSuiteAnalysis {
    $results = @{
        CurrentSuites = @()
        WeakSuites = @()
        StrongSuites = @()
        HasPFS = $false
        HasAEAD = $false
        TLS13Suites = @()
        Compliant = $false
    }
    
    if (Get-Command Get-TlsCipherSuite -ErrorAction SilentlyContinue) {
        $suites = Get-TlsCipherSuite
        $results.CurrentSuites = $suites | Select-Object -ExpandProperty Name
        
        foreach ($suite in $suites) {
            $name = $suite.Name
            
            # Check for weak patterns
            $isWeak = $false
            foreach ($pattern in $Script:Requirements.WeakCipherSuitePatterns) {
                if ($name -like $pattern) {
                    $isWeak = $true
                    $results.WeakSuites += $name
                    break
                }
            }
            
            if (-not $isWeak) {
                $results.StrongSuites += $name
            }
            
            # Check for PFS (ECDHE or DHE)
            if ($name -match 'ECDHE|DHE') {
                $results.HasPFS = $true
            }
            
            # Check for AEAD (GCM, CCM, CHACHA20)
            if ($name -match 'GCM|CCM|CHACHA20') {
                $results.HasAEAD = $true
            }
            
            # TLS 1.3 suites
            if ($name -match '^TLS_AES|^TLS_CHACHA20') {
                $results.TLS13Suites += $name
            }
        }
        
        $results.Compliant = ($results.WeakSuites.Count -eq 0) -and $results.HasPFS -and $results.HasAEAD
    }
    
    return $results
}

function Get-DotNetTlsStatus {
    $paths = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'; Name = '.NET 4.x (64-bit)' }
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'; Name = '.NET 4.x (32-bit)' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'; Name = '.NET 2.0/3.5 (64-bit)' }
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'; Name = '.NET 2.0/3.5 (32-bit)' }
    )
    
    $results = @()
    foreach ($item in $paths) {
        if (Test-Path $item.Path) {
            $strongCrypto = Get-RegistryValue -Path $item.Path -Name 'SchUseStrongCrypto'
            $systemDefault = Get-RegistryValue -Path $item.Path -Name 'SystemDefaultTlsVersions'
            
            $results += [PSCustomObject]@{
                Framework = $item.Name
                SchUseStrongCrypto = if ($null -eq $strongCrypto) { 'Not Set' } elseif ($strongCrypto -eq 1) { 'Enabled' } else { 'Disabled' }
                SystemDefaultTlsVersions = if ($null -eq $systemDefault) { 'Not Set' } elseif ($systemDefault -eq 1) { 'Enabled' } else { 'Disabled' }
                Compliant = ($strongCrypto -eq 1) -and ($systemDefault -eq 1)
            }
        }
    }
    
    return $results
}

function Get-WinHttpStatus {
    $paths = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'; Name = 'WinHTTP (64-bit)' }
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'; Name = 'WinHTTP (32-bit)' }
    )
    
    $results = @()
    foreach ($item in $paths) {
        $secureProtocols = Get-RegistryValue -Path $item.Path -Name 'DefaultSecureProtocols'
        
        $protocols = @()
        if ($secureProtocols) {
            if ($secureProtocols -band 0x00000008) { $protocols += 'SSL 2.0' }
            if ($secureProtocols -band 0x00000020) { $protocols += 'SSL 3.0' }
            if ($secureProtocols -band 0x00000080) { $protocols += 'TLS 1.0' }
            if ($secureProtocols -band 0x00000200) { $protocols += 'TLS 1.1' }
            if ($secureProtocols -band 0x00000800) { $protocols += 'TLS 1.2' }
            if ($secureProtocols -band 0x00002000) { $protocols += 'TLS 1.3' }
        }
        
        $results += [PSCustomObject]@{
            Component = $item.Name
            RawValue = if ($secureProtocols) { "0x{0:X8}" -f $secureProtocols } else { 'Not Set (OS Default)' }
            EnabledProtocols = if ($protocols.Count -gt 0) { $protocols -join ', ' } else { 'OS Default' }
            Compliant = $protocols -contains 'TLS 1.2' -and $protocols -notcontains 'SSL 2.0' -and $protocols -notcontains 'SSL 3.0'
        }
    }
    
    return $results
}

function Get-AdditionalSecurityStatus {
    return [PSCustomObject]@{
        InsecureRenegotiation = @{
            AllowInsecureRenegoClients = Get-RegistryValue -Path $Script:SchannelBasePath -Name 'AllowInsecureRenegoClients'
            AllowInsecureRenegoServers = Get-RegistryValue -Path $Script:SchannelBasePath -Name 'AllowInsecureRenegoServers'
            Compliant = (Get-RegistryValue -Path $Script:SchannelBasePath -Name 'AllowInsecureRenegoClients') -eq 0 -and
                       (Get-RegistryValue -Path $Script:SchannelBasePath -Name 'AllowInsecureRenegoServers') -eq 0
        }
        SCSV = @{
            UseScsvForTls = Get-RegistryValue -Path $Script:SchannelBasePath -Name 'UseScsvForTls'
            Compliant = (Get-RegistryValue -Path $Script:SchannelBasePath -Name 'UseScsvForTls') -eq 1
        }
    }
}
#endregion

#region Output Functions
function Write-ConsoleReport {
    param($AuditResults)
    
    $divider = "=" * 80
    
    Write-Host "`n$divider" -ForegroundColor Cyan
    Write-Host "              SCHANNEL SECURITY AUDIT REPORT" -ForegroundColor Cyan
    Write-Host "              $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "$divider`n" -ForegroundColor Cyan
    
    # System Info
    Write-Host "[i] SYSTEM INFORMATION" -ForegroundColor Yellow
    Write-Host "   Computer: $($AuditResults.SystemInfo.ComputerName)"
    Write-Host "   OS: $($AuditResults.SystemInfo.OSName)"
    Write-Host "   Build: $($AuditResults.SystemInfo.Build)"
    Write-Host ""
    
    # Overall Score
    $score = $AuditResults.ComplianceScore
    $scoreColor = if ($score -ge 90) { 'Green' } elseif ($score -ge 70) { 'Yellow' } else { 'Red' }
    Write-Host "[*] COMPLIANCE SCORE: " -NoNewline -ForegroundColor Yellow
    Write-Host "$score%" -ForegroundColor $scoreColor
    Write-Host ""
    
    # Protocols
    Write-Host "[+] PROTOCOL STATUS" -ForegroundColor Yellow
    Write-Host "   Protocol     Server              Client              Required    Status"
    Write-Host "   ---------------------------------------------------------------------------"
    foreach ($proto in $AuditResults.Protocols) {
        $statusIcon = if ($proto.Compliant) { '[OK]' } else { '[!!]' }
        $serverDisplay = $proto.EffectiveServer.PadRight(18)
        $clientDisplay = $proto.EffectiveClient.PadRight(18)
        $requiredDisplay = $proto.Required.PadRight(10)
        $statusColor = if ($proto.Compliant) { 'Green' } else { 'Red' }
        Write-Host "   $($proto.Protocol.PadRight(10)) $serverDisplay $clientDisplay $requiredDisplay " -NoNewline
        Write-Host $statusIcon -ForegroundColor $statusColor
    }
    Write-Host ""
    
    # Key Exchange
    Write-Host "[+] KEY EXCHANGE" -ForegroundColor Yellow
    $kx = $AuditResults.KeyExchange
    $dhIcon = if ($kx.DiffieHellman.Compliant) { '[OK]' } else { '[!!]' }
    $dhColor = if ($kx.DiffieHellman.Compliant) { 'Green' } else { 'Red' }
    Write-Host "   DH Min Key Bits: $($kx.DiffieHellman.EffectiveMinBits) (Required: $($Script:Requirements.MinDhKeyBits)+) " -NoNewline
    Write-Host $dhIcon -ForegroundColor $dhColor
    Write-Host "   ECDH: $($kx.ECDH.Enabled)"
    Write-Host "   PKCS: $($kx.PKCS.Enabled)"
    Write-Host ""
    
    # Cipher Suites Summary
    Write-Host "[+] CIPHER SUITES" -ForegroundColor Yellow
    $cs = $AuditResults.CipherSuites
    Write-Host "   Total Suites: $($cs.CurrentSuites.Count)"
    Write-Host "   Strong Suites: $($cs.StrongSuites.Count)"
    $weakIcon = if ($cs.WeakSuites.Count -eq 0) { '[OK]' } else { '[!!]' }
    $weakColor = if ($cs.WeakSuites.Count -eq 0) { 'Green' } else { 'Red' }
    Write-Host "   Weak Suites: $($cs.WeakSuites.Count) " -NoNewline
    Write-Host $weakIcon -ForegroundColor $weakColor
    $pfsIcon = if ($cs.HasPFS) { '[OK]' } else { '[!!]' }
    $pfsColor = if ($cs.HasPFS) { 'Green' } else { 'Red' }
    Write-Host "   PFS Support: $(if ($cs.HasPFS) { 'Yes' } else { 'No' }) " -NoNewline
    Write-Host $pfsIcon -ForegroundColor $pfsColor
    $aeadIcon = if ($cs.HasAEAD) { '[OK]' } else { '[!!]' }
    $aeadColor = if ($cs.HasAEAD) { 'Green' } else { 'Red' }
    Write-Host "   AEAD Support: $(if ($cs.HasAEAD) { 'Yes' } else { 'No' }) " -NoNewline
    Write-Host $aeadIcon -ForegroundColor $aeadColor
    Write-Host "   TLS 1.3 Suites: $($cs.TLS13Suites.Count)"
    
    if ($cs.WeakSuites.Count -gt 0) {
        Write-Host "`n   [!] Weak cipher suites detected:" -ForegroundColor Red
        $cs.WeakSuites | ForEach-Object { Write-Host "      - $_" -ForegroundColor Red }
    }
    Write-Host ""
    
    # .NET Framework
    Write-Host "[+] .NET FRAMEWORK TLS" -ForegroundColor Yellow
    foreach ($net in $AuditResults.DotNet) {
        $icon = if ($net.Compliant) { '[OK]' } else { '[!!]' }
        $color = if ($net.Compliant) { 'Green' } else { 'Yellow' }
        Write-Host "   $($net.Framework): StrongCrypto=$($net.SchUseStrongCrypto), SystemDefault=$($net.SystemDefaultTlsVersions) " -NoNewline
        Write-Host $icon -ForegroundColor $color
    }
    Write-Host ""
    
    # Issues Summary
    if ($AuditResults.Issues.Count -gt 0) {
        Write-Host "[!] ISSUES FOUND ($($AuditResults.Issues.Count))" -ForegroundColor Red
        foreach ($issue in $AuditResults.Issues) {
            $severityColor = switch ($issue.Severity) {
                'Critical' { 'Red' }
                'High' { 'Red' }
                'Medium' { 'Yellow' }
                default { 'Gray' }
            }
            Write-Host "   [$($issue.Severity)] $($issue.Description)" -ForegroundColor $severityColor
        }
    } else {
        Write-Host "[OK] NO CRITICAL ISSUES FOUND" -ForegroundColor Green
    }
    
    Write-Host "`n$divider" -ForegroundColor Cyan
}

function Export-HtmlReport {
    param($AuditResults, [string]$Path)
    
    $score = $AuditResults.ComplianceScore
    $scoreColor = if ($score -ge 90) { '#10b981' } elseif ($score -ge 70) { '#f59e0b' } else { '#ef4444' }
    
    # Use single-quoted here-string for CSS to avoid PowerShell parsing issues
    $htmlHead = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Schannel Security Audit Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        header { background: linear-gradient(135deg, #1e40af 0%, #7c3aed 100%); color: white; padding: 2rem; border-radius: 1rem; margin-bottom: 2rem; }
        h1 { font-size: 2rem; }
        .score-badge { display: inline-block; color: white; padding: 0.5rem 1.5rem; border-radius: 9999px; font-size: 1.5rem; font-weight: bold; margin-top: 1rem; }
        .card { background: white; border-radius: 0.75rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 1.5rem; overflow: hidden; }
        .card-header { background: #f1f5f9; padding: 1rem 1.5rem; font-weight: 600; }
        .card-body { padding: 1.5rem; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #f8fafc; }
        .status-ok { color: #10b981; }
        .status-warn { color: #f59e0b; }
        .status-fail { color: #ef4444; }
        .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }
        .badge-critical { background: #fee2e2; color: #991b1b; }
        .badge-high { background: #fef3c7; color: #92400e; }
        .badge-medium { background: #fef9c3; color: #854d0e; }
    </style>
</head>
<body>
    <div class="container">
'@

    # Use double-quoted here-string for dynamic content
    $htmlHeader = @"
        <header>
            <h1>Schannel Security Audit Report</h1>
            <p>$($AuditResults.SystemInfo.ComputerName) | $($AuditResults.SystemInfo.OSName) | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <div class="score-badge" style="background: $scoreColor;">Compliance: $score%</div>
        </header>
        
        <div class="card">
            <div class="card-header">Protocol Status</div>
            <div class="card-body">
                <table>
                    <tr><th>Protocol</th><th>Server</th><th>Client</th><th>Required</th><th>Status</th></tr>
"@
    
    $html = $htmlHead + $htmlHeader

    foreach ($proto in $AuditResults.Protocols) {
        $statusClass = if ($proto.Compliant) { 'status-ok' } else { 'status-fail' }
        $statusText = if ($proto.Compliant) { 'Compliant' } else { 'Non-Compliant' }
        $html += "<tr><td><strong>$($proto.Protocol)</strong></td><td>$($proto.EffectiveServer)</td><td>$($proto.EffectiveClient)</td><td>$($proto.Required)</td><td class='$statusClass'>$statusText</td></tr>"
    }
    
    $html += "</table></div></div>"
    $html += "<div class='card'><div class='card-header'>Issues Found ($($AuditResults.Issues.Count))</div><div class='card-body'>"

    if ($AuditResults.Issues.Count -gt 0) {
        $html += "<table><tr><th>Severity</th><th>Category</th><th>Description</th><th>Recommendation</th></tr>"
        foreach ($issue in $AuditResults.Issues) {
            $badgeClass = "badge-$($issue.Severity.ToLower())"
            $html += "<tr><td><span class='badge $badgeClass'>$($issue.Severity)</span></td><td>$($issue.Category)</td><td>$($issue.Description)</td><td>$($issue.Recommendation)</td></tr>"
        }
        $html += "</table>"
    } else {
        $html += "<p class='status-ok'>No critical issues found. System meets security requirements.</p>"
    }
    
    $html += "</div></div></div></body></html>"

    $html | Out-File -FilePath $Path -Encoding UTF8 -Force
    return $Path
}

function Export-JsonReport {
    param($AuditResults, [string]$Path)
    
    $AuditResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8 -Force
    return $Path
}
#endregion

#region Main Audit Function
function Invoke-SchannelAudit {
    Write-Host "`n[*] Starting Schannel Security Audit..." -ForegroundColor Cyan
    
    $auditResults = @{
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        SystemInfo = @{
            ComputerName = $env:COMPUTERNAME
            OSName = (Get-CimInstance Win32_OperatingSystem).Caption
            Build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).CurrentBuild
        }
        Protocols = @()
        Ciphers = @()
        Hashes = @()
        KeyExchange = $null
        CipherSuites = $null
        DotNet = @()
        WinHttp = @()
        AdditionalSecurity = $null
        Issues = [System.Collections.ArrayList]::new()
        ComplianceScore = 0
    }
    
    # Audit protocols
    Write-Host "   Checking protocols..." -ForegroundColor Gray
    foreach ($proto in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3')) {
        $status = Get-ProtocolStatus -Protocol $proto
        $auditResults.Protocols += $status
        
        if (-not $status.Compliant) {
            [void]$auditResults.Issues.Add([PSCustomObject]@{
                Severity = $status.Severity
                Category = 'Protocol'
                Description = "$proto is not properly configured (Server: $($status.EffectiveServer), Client: $($status.EffectiveClient))"
                Recommendation = if ($status.Required -eq 'Disabled') { "Disable $proto on both Server and Client" } else { "Enable $proto on both Server and Client" }
            })
        }
    }
    
    # Audit ciphers
    Write-Host "   Checking ciphers..." -ForegroundColor Gray
    $cipherNames = @('NULL', 'DES 56', 'Triple DES 168', 'Triple DES 168/168', 'RC2 40/128', 'RC2 56/128', 'RC2 128/128', 'RC4 40/128', 'RC4 56/128', 'RC4 64/128', 'RC4 128/128', 'AES 128/128', 'AES 256/256')
    foreach ($cipher in $cipherNames) {
        $status = Get-CipherStatus -CipherName $cipher
        $auditResults.Ciphers += $status
        
        if (-not $status.Compliant -and $status.IsWeak) {
            $issueDesc = if ($status.Enabled -eq 'Not Set (OS Default)') {
                "Weak cipher '$cipher' is not explicitly disabled (using OS default)"
            } else {
                "Weak cipher '$cipher' is enabled"
            }
            [void]$auditResults.Issues.Add([PSCustomObject]@{
                Severity = $status.Severity
                Category = 'Cipher'
                Description = $issueDesc
                Recommendation = "Disable cipher '$cipher' in Schannel registry"
            })
        }
    }
    
    # Audit hashes
    Write-Host "   Checking hashes..." -ForegroundColor Gray
    foreach ($hash in @('MD5', 'SHA', 'SHA256', 'SHA384', 'SHA512')) {
        $status = Get-HashStatus -HashName $hash
        $auditResults.Hashes += $status
        
        if (-not $status.Compliant -and $status.IsWeak) {
            [void]$auditResults.Issues.Add([PSCustomObject]@{
                Severity = $status.Severity
                Category = 'Hash'
                Description = "Weak hash algorithm '$hash' is enabled"
                Recommendation = "Disable hash '$hash' in Schannel registry"
            })
        }
        
        # Special check: SHA (SHA1) should NOT be disabled - it breaks RDP
        if ($hash -eq 'SHA' -and $status.Enabled -eq 'Disabled') {
            [void]$auditResults.Issues.Add([PSCustomObject]@{
                Severity = 'High'
                Category = 'Hash'
                Description = "SHA (SHA1) is disabled - this will break RDP connections!"
                Recommendation = "Enable SHA hash per Microsoft guidance: Set Enabled to 0xFFFFFFFF"
            })
        }
    }
    
    # Audit key exchange
    Write-Host "   Checking key exchange..." -ForegroundColor Gray
    $auditResults.KeyExchange = Get-KeyExchangeStatus
    
    if (-not $auditResults.KeyExchange.DiffieHellman.Compliant) {
        [void]$auditResults.Issues.Add([PSCustomObject]@{
            Severity = 'Critical'
            Category = 'KeyExchange'
            Description = "DH minimum key length ($($auditResults.KeyExchange.DiffieHellman.EffectiveMinBits) bits) is below requirement ($($Script:Requirements.MinDhKeyBits) bits)"
            Recommendation = "Set ServerMinKeyBitLength and ClientMinKeyBitLength to at least $($Script:Requirements.MinDhKeyBits)"
        })
    }
    
    # Audit cipher suites
    Write-Host "   Checking cipher suites..." -ForegroundColor Gray
    $auditResults.CipherSuites = Get-CipherSuiteAnalysis
    
    if ($auditResults.CipherSuites.WeakSuites.Count -gt 0) {
        [void]$auditResults.Issues.Add([PSCustomObject]@{
            Severity = 'High'
            Category = 'CipherSuite'
            Description = "$($auditResults.CipherSuites.WeakSuites.Count) weak cipher suite(s) enabled"
            Recommendation = "Disable weak cipher suites using Disable-TlsCipherSuite cmdlet"
        })
    }
    
    if (-not $auditResults.CipherSuites.HasPFS) {
        [void]$auditResults.Issues.Add([PSCustomObject]@{
            Severity = 'High'
            Category = 'CipherSuite'
            Description = "No cipher suites with Perfect Forward Secrecy (PFS) enabled"
            Recommendation = "Enable ECDHE or DHE cipher suites."
        })
    }
    
    # Audit .NET
    Write-Host "   Checking .NET Framework..." -ForegroundColor Gray
    $auditResults.DotNet = Get-DotNetTlsStatus
    
    # Audit WinHTTP
    Write-Host "   Checking WinHTTP..." -ForegroundColor Gray
    $auditResults.WinHttp = Get-WinHttpStatus
    
    # Audit additional security
    Write-Host "   Checking additional security settings..." -ForegroundColor Gray
    $auditResults.AdditionalSecurity = Get-AdditionalSecurityStatus
    
    # Calculate compliance score
    $totalChecks = 0
    $passedChecks = 0
    
    # Protocol compliance
    foreach ($proto in $auditResults.Protocols) {
        $totalChecks += 2  # Server and Client
        if ($proto.Compliant) { $passedChecks += 2 }
    }
    
    # Cipher suite compliance
    $totalChecks += 3
    if ($auditResults.CipherSuites.WeakSuites.Count -eq 0) { $passedChecks++ }
    if ($auditResults.CipherSuites.HasPFS) { $passedChecks++ }
    if ($auditResults.CipherSuites.HasAEAD) { $passedChecks++ }
    
    # Key exchange compliance
    $totalChecks++
    if ($auditResults.KeyExchange.DiffieHellman.Compliant) { $passedChecks++ }
    
    $auditResults.ComplianceScore = [math]::Round(($passedChecks / $totalChecks) * 100)
    
    Write-Host "   Audit complete.`n" -ForegroundColor Green
    
    return [PSCustomObject]$auditResults
}
#endregion

#region Main Execution
$results = Invoke-SchannelAudit

switch ($OutputFormat) {
    'Console' {
        Write-ConsoleReport -AuditResults $results
    }
    'HTML' {
        $htmlPath = Join-Path $OutputPath "SchannelAudit_$Script:Timestamp.html"
        $file = Export-HtmlReport -AuditResults $results -Path $htmlPath
        Write-Host "HTML report saved: $file" -ForegroundColor Green
    }
    'JSON' {
        $jsonPath = Join-Path $OutputPath "SchannelAudit_$Script:Timestamp.json"
        $file = Export-JsonReport -AuditResults $results -Path $jsonPath
        Write-Host "JSON report saved: $file" -ForegroundColor Green
    }
    'All' {
        Write-ConsoleReport -AuditResults $results
        
        $htmlPath = Join-Path $OutputPath "SchannelAudit_$Script:Timestamp.html"
        Export-HtmlReport -AuditResults $results -Path $htmlPath | Out-Null
        
        $jsonPath = Join-Path $OutputPath "SchannelAudit_$Script:Timestamp.json"
        Export-JsonReport -AuditResults $results -Path $jsonPath | Out-Null
        
        Write-Host "`nReports saved to:" -ForegroundColor Cyan
        Write-Host "   HTML: $htmlPath" -ForegroundColor Gray
        Write-Host "   JSON: $jsonPath" -ForegroundColor Gray
    }
}

return $results
#endregion
