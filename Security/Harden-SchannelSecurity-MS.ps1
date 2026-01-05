<#
.SYNOPSIS
    Windows Schannel TLS/SSL Security Hardening - Production Tested Configuration
    Based on: Microsoft AskDS recommendations + IISCrypto best practices

.DESCRIPTION
    Implements comprehensive Schannel hardening that has been tested and confirmed
    working on Windows Server 2019 Domain Controller without breaking RDP.

    WHAT THIS SCRIPT CONFIGURES:
    ============================

    Schannel Security Settings:
    - AllowInsecureRenegoClients = 0 (disabled)
    - AllowInsecureRenegoServers = 0 (disabled)
    - UseScsvForTls = 1 (enabled - TLS Fallback SCSV protection)
    - EventLogging = 1 (basic) or 7 (verbose)

    Protocols DISABLED:
    - Multi-Protocol Unified Hello
    - PCT 1.0
    - SSL 2.0, SSL 3.0
    - TLS 1.0, TLS 1.1 (Server 2012 R2+)
    - DTLS 1.0

    Protocols ENABLED:
    - TLS 1.2
    - TLS 1.3 (on supported systems - Server 2022+, Win10 20H2+)
    - DTLS 1.2

    Ciphers DISABLED (Enabled=0):
    - NULL, DES 56, DES 56/56
    - RC2 40/128, RC2 56/128, RC2 56/56, RC2 128/128
    - RC4 40/128, RC4 56/128, RC4 64/128, RC4 128/128
    - Triple DES 168, Triple DES 168/168

    Ciphers ENABLED (Enabled=0xFFFFFFFF):
    - AES 128/128, AES 256/256

    Hashes:
    - MD5: Disabled (0)
    - SHA, SHA256, SHA384, SHA512: Enabled (0xFFFFFFFF)

    Key Exchange:
    - Diffie-Hellman: Enabled, MinKeyBitLength=2048
    - ECDH: Enabled, ClientMinKeyBitLength=2048, EphemKeyReuseTime=0 (Server 2022+)
    - PKCS: Enabled

    .NET Framework:
    - SystemDefaultTlsVersions = 1
    - SchUseStrongCrypto = 1

    WinHTTP:
    - DefaultSecureProtocols = 0x2800 (TLS 1.2 + 1.3) for Server 2012 R2+
    - DefaultSecureProtocols = 0x0A00 (TLS 1.2 only) for Server 2012

    VERSION-SPECIFIC BEHAVIOR:
    - Server 2008/2008 R2 (Build <9200): BLOCKED - End of Life, incompatible
    - Server 2012 (Build 9200): Conservative TLS 1.2-only approach
    - Server 2012 R2+ (Build 9600+): Full modern hardening

.PARAMETER MinDhKeyBits
    Minimum DH/ECDH key length. Default: 2048

.PARAMETER WinHttpProtocols
    WinHTTP DefaultSecureProtocols value. Default: Auto-detected based on OS version
    Server 2012: 0x0A00 (TLS 1.2 only)
    Server 2012 R2+: 0x2800 (TLS 1.2 + 1.3)

.PARAMETER EnableVerboseLogging
    Enable verbose Schannel logging (EventLogging=7). Default: $false

.PARAMETER BackupPath
    Path for registry backup. Default: $env:TEMP

.PARAMETER Force
    Bypass Windows Server 2008/2008 R2 blocking (NOT RECOMMENDED - may break system)

.EXAMPLE
    .\Harden-SchannelSecurity-MS.ps1 -WhatIf
    Preview changes without applying.

.EXAMPLE
    .\Harden-SchannelSecurity-MS.ps1 -Confirm:$false
    Apply hardening without confirmation prompts.

.EXAMPLE
    .\Harden-SchannelSecurity-MS.ps1 -MinDhKeyBits 3072
    Use 3072-bit minimum key length for DH/ECDH.

.NOTES
    Author:         Karol Kula (cquresphere)
    Version:        2.2.0
    Tested On:      Windows Server 2012, 2012 R2, 2016, 2019, 2022
    Reference:      Microsoft AskDS Team + IISCrypto

    Supported Versions:
    - Windows Server 2012 (Build 9200): Minimum supported version
    - Windows Server 2012 R2+ (Build 9600+): Full feature support
    - Windows Server 2008/2008 R2: BLOCKED (End of Life)

    Changelog:
    - 2.2.0: Added version detection for Server 2008/2012, version-specific settings
    - 1.1.0: Added missing EphemKeyReuseTime for PFS, fixed ShouldProcess warnings
    - 1.0.0: Initial production-tested version
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet(1024, 2048, 3072, 4096)]
    [int]$MinDhKeyBits = 2048,

    [int]$WinHttpProtocols = 0,  # 0 = Auto-detect based on OS version

    [switch]$EnableVerboseLogging,

    [string]$BackupPath = $env:TEMP,

    [switch]$Force
)

#region Configuration
$Script:SchannelBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
$Script:Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Script:LogFile = Join-Path $BackupPath "SchannelHardening_$Script:Timestamp.log"
$Script:AppliedCount = 0
$Script:SkippedCount = 0
$Script:OsBuild = 0
$Script:OsVersion = ""
#endregion Configuration

#region Logging
function Write-Log {
    param(
        [AllowEmptyString()]
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK', 'SKIP')]
        [string]$Level = 'INFO'
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { Write-Host ""; return }

    $icons = @{ INFO = '[*]'; WARN = '[!]'; ERROR = '[X]'; OK = '[+]'; SKIP = '[-]' }
    $colors = @{ INFO = 'Cyan'; WARN = 'Yellow'; ERROR = 'Red'; OK = 'Green'; SKIP = 'DarkGray' }

    $line = "$(Get-Date -Format 'HH:mm:ss') $($icons[$Level]) $Message"
    Write-Host $line -ForegroundColor $colors[$Level]
    Add-Content -Path $Script:LogFile -Value $line -ErrorAction SilentlyContinue
}
#endregion Logging

#region Version Detection
function Test-WindowsVersion {
    param([switch]$Force)

    $Script:OsBuild = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).CurrentBuildNumber
    $productName = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).ProductName

    # Build number reference:
    # Server 2008 R2 = 7600-7601
    # Server 2012 = 9200
    # Server 2012 R2 = 9600
    # Server 2016 = 14393
    # Server 2019 = 17763
    # Server 2022 = 20348

    switch ($Script:OsBuild) {
        { $_ -lt 7600 } {
            $Script:OsVersion = "Pre-2008 R2"
            $supported = $false
        }
        { $_ -ge 7600 -and $_ -lt 9200 } {
            $Script:OsVersion = "Server 2008 R2"
            $supported = $false
        }
        9200 {
            $Script:OsVersion = "Server 2012"
            $supported = $true
        }
        9600 {
            $Script:OsVersion = "Server 2012 R2"
            $supported = $true
        }
        { $_ -ge 10240 -and $_ -lt 14393 } {
            $Script:OsVersion = "Windows 10 / Server 2016"
            $supported = $true
        }
        { $_ -ge 14393 -and $_ -lt 17763 } {
            $Script:OsVersion = "Server 2016"
            $supported = $true
        }
        { $_ -ge 17763 -and $_ -lt 20348 } {
            $Script:OsVersion = "Server 2019"
            $supported = $true
        }
        { $_ -ge 20348 } {
            $Script:OsVersion = "Server 2022+"
            $supported = $true
        }
        default {
            $Script:OsVersion = "Unknown ($Script:OsBuild)"
            $supported = $false
        }
    }

    if (-not $supported) {
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Red
        Write-Host "   ERROR: UNSUPPORTED WINDOWS VERSION DETECTED" -ForegroundColor Red
        Write-Host ("=" * 80) -ForegroundColor Red
        Write-Host ""
        Write-Host "Detected OS: $productName (Build $Script:OsBuild)" -ForegroundColor Yellow
        Write-Host "Classification: $Script:OsVersion" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "This script requires Windows Server 2012 (Build 9200) or later" -ForegroundColor Red
        Write-Host ""
        Write-Host "Windows Server 2008/2008 R2 considerations:" -ForegroundColor Yellow
        Write-Host "  - End of Life (EOL): January 14, 2020" -ForegroundColor Yellow
        Write-Host "  - No security updates available" -ForegroundColor Yellow
        Write-Host "  - Limited TLS 1.2 support (requires KB3080079 + registry changes)" -ForegroundColor Yellow
        Write-Host "  - No TLS 1.3 support" -ForegroundColor Yellow
        Write-Host "  - Different cipher suite capabilities" -ForegroundColor Yellow
        Write-Host "  - Incompatible with modern security requirements" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "RECOMMENDATION: Upgrade to Windows Server 2012 R2 or later" -ForegroundColor Green
        Write-Host ""

        if ($Force) {
            Write-Host "WARNING: -Force specified, proceeding anyway (NOT RECOMMENDED)" -ForegroundColor Red
            Write-Host "         This may break your system or cause security issues!" -ForegroundColor Red
            Write-Host ""
            Write-Log "FORCED execution on unsupported OS: $Script:OsVersion (Build $Script:OsBuild)" -Level WARN
            return $true
        }

        throw "Unsupported Windows version. Script execution aborted. Use -Force to override (NOT RECOMMENDED)."
    }

    return $true
}
#endregion Version Detection

#region Registry Helpers
function Set-RegistryValue {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Description
    )

    if (-not (Test-Path $Path)) {
        if ($PSCmdlet.ShouldProcess($Path, "Create key")) {
            New-Item -Path $Path -Force | Out-Null
        }
    }

    $current = $null
    try { $current = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).$Name } catch { }

    if ($current -ne $Value) {
        if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value")) {
            New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
            Write-Log "$Description : $current -> $Value" -Level OK
            $Script:AppliedCount++
        }
    } else {
        Write-Log "$Description : Already $Value" -Level SKIP
        $Script:SkippedCount++
    }
}

function Set-CipherValue {
    <#
    .SYNOPSIS
        Sets cipher registry value using .NET Registry class to handle "/" in names.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$CipherName,
        [int]$Value,
        [string]$Description
    )

    $regPath = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$CipherName"

    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($regPath)
        if ($null -eq $key) {
            Write-Log "Failed to create key for $CipherName" -Level ERROR
            return
        }

        $current = $key.GetValue('Enabled', $null)

        if ($current -ne $Value) {
            if ($PSCmdlet.ShouldProcess($CipherName, "Set Enabled to $Value")) {
                $key.SetValue('Enabled', $Value, [Microsoft.Win32.RegistryValueKind]::DWord)
                Write-Log "$Description : $current -> $Value" -Level OK
                $Script:AppliedCount++
            }
        } else {
            Write-Log "$Description : Already $Value" -Level SKIP
            $Script:SkippedCount++
        }

        $key.Close()
    } catch {
        Write-Log "Error setting $CipherName : $_" -Level ERROR
    }
}
#endregion Registry Helpers

#region Backup
function New-Backup {
    $backupFile = Join-Path $BackupPath "SchannelBackup_$Script:Timestamp.reg"
    Write-Log "Creating backup: $backupFile" -Level INFO

    @(
        'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
        'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework'
        'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework'
        'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
        'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
    ) | ForEach-Object {
        $temp = [IO.Path]::GetTempFileName()
        $null = reg export $_ $temp /y 2>&1
        if (Test-Path $temp) {
            Get-Content $temp -ErrorAction SilentlyContinue | Add-Content $backupFile
            Remove-Item $temp -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Log "Backup created" -Level OK
    return $backupFile
}
#endregion Backup

#region Schannel Base Settings
function Set-SchannelBaseSettings {
    Write-Log ""
    Write-Log "=== SCHANNEL BASE SETTINGS ===" -Level INFO

    # Disable insecure renegotiation (CVE-2009-3555 mitigation)
    Set-RegistryValue -Path $Script:SchannelBase -Name 'AllowInsecureRenegoClients' -Value 0 -Description "AllowInsecureRenegoClients"
    Set-RegistryValue -Path $Script:SchannelBase -Name 'AllowInsecureRenegoServers' -Value 0 -Description "AllowInsecureRenegoServers"

    # Enable TLS Fallback SCSV (RFC 7507 - downgrade attack protection)
    Set-RegistryValue -Path $Script:SchannelBase -Name 'UseScsvForTls' -Value 1 -Description "UseScsvForTls"

    # Event logging
    $logValue = if ($EnableVerboseLogging) { 7 } else { 1 }
    Set-RegistryValue -Path $Script:SchannelBase -Name 'EventLogging' -Value $logValue -Description "EventLogging"
}
#endregion Schannel Base Settings

#region Protocol Configuration
function Set-Protocols {
    Write-Log ""
    Write-Log "=== PROTOCOLS ===" -Level INFO

    # Version-specific protocol handling
    if ($Script:OsBuild -eq 9200) {
        # Server 2012: Conservative approach - TLS 1.0/1.1 may still be needed
        Write-Log "Detected Server 2012 - Using conservative protocol configuration" -Level WARN

        $disableProtocols = @(
            'Multi-Protocol Unified Hello'
            'PCT 1.0'
            'SSL 2.0'
            'SSL 3.0'
            'DTLS 1.0'
        )

        # For Server 2012, we keep TLS 1.0/1.1 enabled but with warning
        Write-Log "TLS 1.0/1.1: Left enabled for Server 2012 compatibility" -Level WARN
        Write-Log "Consider disabling TLS 1.0/1.1 after verifying application compatibility" -Level WARN

        $enableProtocols = @(
            'TLS 1.0'
            'TLS 1.1'
            'TLS 1.2'
            'DTLS 1.2'
        )
    } else {
        # Server 2012 R2+: Full hardening
        $disableProtocols = @(
            'Multi-Protocol Unified Hello'
            'PCT 1.0'
            'SSL 2.0'
            'SSL 3.0'
            'TLS 1.0'
            'TLS 1.1'
            'DTLS 1.0'
        )

        $enableProtocols = @(
            'TLS 1.2'
            'DTLS 1.2'
        )
    }

    # Disable weak protocols
    foreach ($proto in $disableProtocols) {
        Write-Log "Disabling: $proto" -Level INFO
        foreach ($side in @('Client', 'Server')) {
            $path = "$Script:SchannelBase\Protocols\$proto\$side"
            Set-RegistryValue -Path $path -Name 'Enabled' -Value 0 -Description "$proto $side Enabled"
            Set-RegistryValue -Path $path -Name 'DisabledByDefault' -Value 1 -Description "$proto $side DisabledByDefault"
        }
    }

    # Enable strong protocols
    foreach ($proto in $enableProtocols) {
        Write-Log "Enabling: $proto" -Level INFO
        foreach ($side in @('Client', 'Server')) {
            $path = "$Script:SchannelBase\Protocols\$proto\$side"
            Set-RegistryValue -Path $path -Name 'Enabled' -Value 1 -Description "$proto $side Enabled"
            Set-RegistryValue -Path $path -Name 'DisabledByDefault' -Value 0 -Description "$proto $side DisabledByDefault"
        }
    }

    # TLS 1.3 - Enable on supported systems (Server 2022+, Win10 20H2+ - Build 19042+)
    if ($Script:OsBuild -ge 19042) {
        Write-Log "Enabling: TLS 1.3 (Build $Script:OsBuild)" -Level INFO
        foreach ($side in @('Client', 'Server')) {
            $path = "$Script:SchannelBase\Protocols\TLS 1.3\$side"
            Set-RegistryValue -Path $path -Name 'Enabled' -Value 1 -Description "TLS 1.3 $side Enabled"
            Set-RegistryValue -Path $path -Name 'DisabledByDefault' -Value 0 -Description "TLS 1.3 $side DisabledByDefault"
        }
    } else {
        Write-Log "TLS 1.3: Not supported on Build $Script:OsBuild (requires 19042+)" -Level INFO
    }
}
#endregion Protocol Configuration

#region Cipher Configuration
function Set-Ciphers {
    Write-Log ""
    Write-Log "=== CIPHERS ===" -Level INFO

    # Ciphers to DISABLE (Enabled=0)
    $disableCiphers = @(
        'NULL'
        'DES 56'
        'DES 56/56'
        'RC2 40/128'
        'RC2 56/128'
        'RC2 56/56'
        'RC2 128/128'
        'RC4 40/128'
        'RC4 56/128'
        'RC4 64/128'
        'RC4 128/128'
        'Triple DES 168'
        'Triple DES 168/168'
    )

    Write-Log "Disabling weak ciphers..." -Level INFO
    foreach ($cipher in $disableCiphers) {
        Set-CipherValue -CipherName $cipher -Value 0 -Description "Disable $cipher"
    }

    # Ciphers to ENABLE (Enabled=0xFFFFFFFF)
    $enableCiphers = @(
        'AES 128/128'
        'AES 256/256'
    )

    Write-Log "Enabling strong ciphers..." -Level INFO
    foreach ($cipher in $enableCiphers) {
        Set-CipherValue -CipherName $cipher -Value 0xFFFFFFFF -Description "Enable $cipher"
    }
}
#endregion Cipher Configuration

#region Hash Configuration
function Set-Hashes {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Log ""
    Write-Log "=== HASHES ===" -Level INFO

    # MD5 - DISABLE
    Write-Log "Disabling: MD5" -Level INFO
    Set-RegistryValue -Path "$Script:SchannelBase\Hashes\MD5" -Name 'Enabled' -Value 0 -Description "MD5 Enabled"

    # SHA, SHA256, SHA384, SHA512 - ENABLE with 0xFFFFFFFF
    $enableHashes = @('SHA', 'SHA256', 'SHA384', 'SHA512')

    Write-Log "Enabling: SHA, SHA256, SHA384, SHA512" -Level INFO
    foreach ($hash in $enableHashes) {
        $path = "$Script:SchannelBase\Hashes\$hash"
        if (-not (Test-Path $path)) {
            if ($PSCmdlet.ShouldProcess($path, "Create key")) {
                New-Item -Path $path -Force | Out-Null
            }
        }
        if ($PSCmdlet.ShouldProcess("$path\Enabled", "Set to 0xFFFFFFFF")) {
            New-ItemProperty -Path $path -Name 'Enabled' -PropertyType DWord -Value 0xFFFFFFFF -Force | Out-Null
            Write-Log "$hash Enabled: 0xFFFFFFFF" -Level OK
            $Script:AppliedCount++
        }
    }
}
#endregion Hash Configuration

#region Key Exchange Configuration
function Set-KeyExchange {
    Write-Log ""
    Write-Log "=== KEY EXCHANGE ===" -Level INFO

    # Diffie-Hellman
    Write-Log "Configuring Diffie-Hellman (MinKeyBitLength=$MinDhKeyBits)" -Level INFO
    $dhPath = "$Script:SchannelBase\KeyExchangeAlgorithms\Diffie-Hellman"
    Set-RegistryValue -Path $dhPath -Name 'Enabled' -Value 0xFFFFFFFF -Description "DH Enabled"
    Set-RegistryValue -Path $dhPath -Name 'ServerMinKeyBitLength' -Value $MinDhKeyBits -Description "DH ServerMinKeyBitLength"
    Set-RegistryValue -Path $dhPath -Name 'ClientMinKeyBitLength' -Value $MinDhKeyBits -Description "DH ClientMinKeyBitLength"

    # ECDH
    Write-Log "Configuring ECDH (ClientMinKeyBitLength=$MinDhKeyBits)" -Level INFO
    $ecdhPath = "$Script:SchannelBase\KeyExchangeAlgorithms\ECDH"
    Set-RegistryValue -Path $ecdhPath -Name 'Enabled' -Value 0xFFFFFFFF -Description "ECDH Enabled"
    Set-RegistryValue -Path $ecdhPath -Name 'ClientMinKeyBitLength' -Value $MinDhKeyBits -Description "ECDH ClientMinKeyBitLength"

    # EphemKeyReuseTime - Only effective on Server 2022+ (Build 20348+)
    # Setting to 0 = never reuse ephemeral keys (maximum PFS)
    # NOTE: This is NOT a Microsoft-documented setting and NOT in CIS benchmarks
    # It addresses Qualys SSL Labs "ECDH public server param reuse" warning
    if ($Script:OsBuild -ge 20348) {
        Set-RegistryValue -Path $ecdhPath -Name 'EphemKeyReuseTime' -Value 0 -Description "ECDH EphemKeyReuseTime (0=no reuse, PFS)"
    } else {
        Write-Log "EphemKeyReuseTime: Skipped (only effective on Server 2022+, current build: $Script:OsBuild)" -Level INFO
    }

    # PKCS
    Write-Log "Enabling PKCS" -Level INFO
    $pkcsPath = "$Script:SchannelBase\KeyExchangeAlgorithms\PKCS"
    Set-RegistryValue -Path $pkcsPath -Name 'Enabled' -Value 0xFFFFFFFF -Description "PKCS Enabled"
}
#endregion Key Exchange Configuration

#region .NET Framework Configuration
function Set-DotNetFramework {
    Write-Log ""
    Write-Log "=== .NET FRAMEWORK ===" -Level INFO

    $netPaths = @(
        'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'
        'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    )

    foreach ($path in $netPaths) {
        $shortPath = $path -replace 'HKLM:\\SOFTWARE\\', ''
        Write-Log "Configuring: $shortPath" -Level INFO
        Set-RegistryValue -Path $path -Name 'SystemDefaultTlsVersions' -Value 1 -Description "SystemDefaultTlsVersions"
        Set-RegistryValue -Path $path -Name 'SchUseStrongCrypto' -Value 1 -Description "SchUseStrongCrypto"
    }
}
#endregion .NET Framework Configuration

#region WinHTTP Configuration
function Set-WinHttp {
    Write-Log ""
    Write-Log "=== WINHTTP ===" -Level INFO

    # Auto-detect WinHTTP protocol value if not specified
    $actualProtocols = if ($WinHttpProtocols -eq 0) {
        if ($Script:OsBuild -eq 9200) {
            # Server 2012: TLS 1.2 only (conservative)
            0x0A00
        } else {
            # Server 2012 R2+: TLS 1.2 + 1.3
            0x2800
        }
    } else {
        $WinHttpProtocols
    }

    $protoDesc = switch ($actualProtocols) {
        0xAA0  { "TLS 1.0 + 1.1 + 1.2" }
        0x2800 { "TLS 1.2 + 1.3" }
        0x0A00 { "TLS 1.2 only" }
        0xA80  { "TLS 1.1 + 1.2" }
        0x800  { "TLS 1.2 only (alternate)" }
        default { "0x$($actualProtocols.ToString('X'))" }
    }

    if ($Script:OsBuild -eq 9200) {
        Write-Log "DefaultSecureProtocols: $protoDesc (Server 2012 conservative)" -Level WARN
    } else {
        Write-Log "DefaultSecureProtocols: $protoDesc" -Level INFO
    }

    $winHttpPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
    )

    foreach ($path in $winHttpPaths) {
        Set-RegistryValue -Path $path -Name 'DefaultSecureProtocols' -Value $actualProtocols -Description "WinHTTP DefaultSecureProtocols"
    }
}
#endregion WinHTTP Configuration

#region Disable NULL Cipher Suites
function Disable-NullCipherSuites {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Log ""
    Write-Log "=== NULL CIPHER SUITES ===" -Level INFO

    if (-not (Get-Command Disable-TlsCipherSuite -ErrorAction SilentlyContinue)) {
        Write-Log "Disable-TlsCipherSuite cmdlet not available" -Level WARN
        return
    }

    $nullSuites = @(
        'TLS_RSA_WITH_NULL_SHA256'
        'TLS_RSA_WITH_NULL_SHA'
        'TLS_PSK_WITH_NULL_SHA384'
        'TLS_PSK_WITH_NULL_SHA256'
        'TLS_PSK_WITH_NULL_SHA'
    )

    foreach ($suite in $nullSuites) {
        try {
            $exists = Get-TlsCipherSuite -Name $suite -ErrorAction SilentlyContinue
            if ($exists) {
                if ($PSCmdlet.ShouldProcess($suite, "Disable")) {
                    Disable-TlsCipherSuite -Name $suite -ErrorAction Stop
                    Write-Log "Disabled: $suite" -Level OK
                    $Script:AppliedCount++
                }
            }
        } catch {
            Write-Log "Could not disable $suite" -Level WARN
        }
    }
}
#endregion Disable NULL Cipher Suites

#region Main
function Invoke-Hardening {
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "   SCHANNEL SECURITY HARDENING - PRODUCTION TESTED v2.2" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""

    # Version check
    Test-WindowsVersion -Force:$Force | Out-Null

    $os = Get-CimInstance Win32_OperatingSystem

    Write-Log "Computer: $($env:COMPUTERNAME)" -Level INFO
    Write-Log "OS: $($os.Caption) (Build $Script:OsBuild)" -Level INFO
    Write-Log "Detected Version: $Script:OsVersion" -Level INFO
    Write-Log "Log: $Script:LogFile" -Level INFO
    Write-Log ""
    Write-Log "Configuration:" -Level INFO
    Write-Log "  Min DH/ECDH Key Bits: $MinDhKeyBits" -Level INFO
    Write-Log "  Verbose Logging: $EnableVerboseLogging" -Level INFO

    if ($Script:OsBuild -eq 9200) {
        Write-Log ""
        Write-Log "SERVER 2012 DETECTED - CONSERVATIVE MODE ACTIVE" -Level WARN
        Write-Log "  - TLS 1.0/1.1 will remain ENABLED for compatibility" -Level WARN
        Write-Log "  - Test thoroughly before disabling TLS 1.0/1.1" -Level WARN
        Write-Log "  - Consider upgrading to Server 2012 R2+ for full hardening" -Level WARN
    }

    # Backup
    Write-Log ""
    $backupFile = New-Backup

    # Apply settings
    Set-SchannelBaseSettings
    Set-Protocols
    Set-Ciphers
    Set-Hashes
    Set-KeyExchange
    Set-DotNetFramework
    Set-WinHttp
    Disable-NullCipherSuites

    # Summary
    Write-Log ""
    Write-Log ("=" * 80) -Level INFO
    Write-Log "HARDENING COMPLETE" -Level OK
    Write-Log ("=" * 80) -Level INFO
    Write-Log "OS Version: $Script:OsVersion (Build $Script:OsBuild)" -Level INFO
    Write-Log "Applied: $Script:AppliedCount" -Level INFO
    Write-Log "Already configured: $Script:SkippedCount" -Level INFO
    Write-Log ""
    Write-Log "Backup: $backupFile" -Level INFO
    Write-Log "Log: $Script:LogFile" -Level INFO
    Write-Log ""
    Write-Log "!!! REBOOT REQUIRED FOR CHANGES TO TAKE EFFECT !!!" -Level WARN
    Write-Log ""
    Write-Log "To rollback: reg import `"$backupFile`"" -Level INFO
    Write-Log ""

    if ($Script:OsBuild -eq 9200) {
        Write-Log "SERVER 2012 POST-HARDENING NOTES:" -Level WARN
        Write-Log "  1. TLS 1.0/1.1 remain enabled for compatibility" -Level WARN
        Write-Log "  2. Monitor application compatibility after reboot" -Level WARN
        Write-Log "  3. Plan migration to Server 2016+ for full security" -Level WARN
        Write-Log ""
    }

    return [PSCustomObject]@{
        Success = $true
        Applied = $Script:AppliedCount
        Skipped = $Script:SkippedCount
        BackupFile = $backupFile
        LogFile = $Script:LogFile
        OsVersion = $Script:OsVersion
        OsBuild = $Script:OsBuild
    }
}

$result = Invoke-Hardening
return $result
#endregion Main
