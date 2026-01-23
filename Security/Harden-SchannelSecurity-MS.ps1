<#
.SYNOPSIS
    Windows Schannel TLS/SSL Security Hardening - Production Tested Configuration
    Based on: Microsoft TLS Registry Settings + IISCrypto best practices

.DESCRIPTION
    Implements comprehensive Schannel hardening that has been tested and confirmed
    working on Windows Server 2012+ including Domain Controllers without breaking RDP.

    WHAT THIS SCRIPT CONFIGURES:
    ============================

    Schannel Security Settings:
    - AllowInsecureRenegoClients = 0 (disabled - CVE-2009-3555 mitigation)
    - AllowInsecureRenegoServers = 0 (disabled - CVE-2009-3555 mitigation)
    - UseScsvForTls = 1 (enabled - TLS Fallback SCSV protection, RFC 7507)
    - DisableCompression = 1 (disabled - CRIME attack mitigation)
    - EventLogging = 0-7 (configurable, default: 1 = Error events only)

    OCSP Stapling (Optional):
    - EnableOcspStaplingForSni = 0/1 (default: not configured)
    - Improves TLS performance, reduces OCSP server load
    - Use -EnableOcspStapling parameter

    Protocols DISABLED:
    - Multi-Protocol Unified Hello
    - PCT 1.0
    - SSL 2.0, SSL 3.0
    - TLS 1.0, TLS 1.1 (Server 2012 R2+)
    - DTLS 1.0

    Protocols ENABLED:
    - TLS 1.2
    - TLS 1.3 (on supported systems - Server 2022+, Win10 20H2+ Build 19042+)
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

    Key Exchange Algorithms:
    - Diffie-Hellman: Enabled, MinKeyBitLength=2048 (configurable 1024-4096)
    - ECDH: Enabled, ClientMinKeyBitLength=2048, EphemKeyReuseTime=0 (Server 2022+)
    - PKCS/RSA: Enabled, ClientMinKeyBitLength=2048 (NEW in v3.0.0)
    - ECC Curve Priority: P-384, P-256, curve25519 (Server 2016+)

    Cipher Suite Ordering (Optional):
    - Prioritizes ECDHE suites with AES-GCM for Perfect Forward Secrecy
    - Server-side cipher suite selection (not client)
    - Use -EnableCipherSuiteOrder parameter to configure

    Session Cache (Optional):
    - Default: 10-hour cache, 20,000 elements max (~60MB memory)
    - High-security mode: Disable with -DisableSessionCache (forces full handshake)
    - Configurable with -MaximumCacheSize parameter

    Trusted Issuer List (Optional):
    - Default: Don't send trusted CA list to clients (0)
    - Enable with -SendTrustedIssuerList (may leak PKI info)

    .NET Framework:
    - SystemDefaultTlsVersions = 1 (v2.0.50727 + v4.0.30319, x86 + x64)
    - SchUseStrongCrypto = 1 (v2.0.50727 + v4.0.30319, x86 + x64)

    WinHTTP:
    - DefaultSecureProtocols = 0x2800 (TLS 1.2 + 1.3) for Server 2022+ / Win10 20H2+ (Build 19042+)
    - DefaultSecureProtocols = 0x0800 (TLS 1.2 only) for Server 2012/2012 R2/2016/2019

    APPLICATION-LEVEL SECURITY (NOT CONFIGURED BY THIS SCRIPT):
    ============================================================
    The following must be configured at the web server/application level:

    - HTTP Strict Transport Security (HSTS): CRITICAL for preventing protocol downgrade attacks
      * Recommended header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
      * Configure in IIS, Apache, Nginx, or application code
      * Consider HSTS preload list submission: https://hstspreload.org/

    - Content Security Policy (CSP): Prevents XSS and mixed-content vulnerabilities
      * Example: Content-Security-Policy: default-src https: 'unsafe-inline' 'unsafe-eval'
      * Configure in web server or application headers

    - Secure Cookies: Mark all cookies with Secure and HttpOnly flags
      * Prevents cookie theft over unencrypted connections
      * Configure in application code or web server

    - Certificate Configuration:
      * Use 2048-bit RSA minimum (3072-bit for high security)
      * Consider ECDSA P-256 certificates for better performance
      * Deploy complete certificate chains (leaf + intermediates)
      * Implement OCSP stapling in IIS/web server
      * Use DNS CAA records to restrict certificate issuance

    References:
    - SSL Labs Best Practices: https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
    - OWASP TLS Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html

    VERSION-SPECIFIC BEHAVIOR:
    - Server 2008/2008 R2 (Build <9200): BLOCKED - End of Life, incompatible
    - Server 2012 (Build 9200): Conservative TLS 1.2-only approach
    - Server 2012 R2+ (Build 9600+): Full modern hardening
    - Server 2022+ (Build 20348+): Enhanced PFS with EphemKeyReuseTime=0

.PARAMETER MinDhKeyBits
    Minimum key length for Diffie-Hellman, ECDH, and PKCS/RSA key exchange algorithms.
    Valid values: 1024, 2048, 3072, 4096
    Default: 2048
    Recommendation: Use 2048 minimum, 3072 for high-security environments

.PARAMETER WinHttpProtocols
    WinHTTP DefaultSecureProtocols registry value (DWORD).
    Default: 0 (auto-detect based on OS version)
    - Server 2012/2012 R2/2016/2019: Auto-detects to 0x0800 (TLS 1.2 only)
    - Server 2022+ / Win10 20H2+ (Build 19042+): Auto-detects to 0x2800 (TLS 1.2 + 1.3)
    Common values:
    - 0x0800 = TLS 1.2 only
    - 0x0A00 = TLS 1.1 + 1.2
    - 0x2800 = TLS 1.2 + 1.3
    - 0x0A80 = TLS 1.0 + 1.1 + 1.2 (not recommended)

.PARAMETER EventLogging
    Schannel event logging level (0-7).
    Default: 1 (Error events only)
    Values:
    - 0 = No events
    - 1 = Error events only (recommended default)
    - 2 = Warning events only
    - 3 = Error + Warning
    - 4 = Info + Success events
    - 5 = Error + Info + Success
    - 6 = Warning + Info + Success
    - 7 = All events (Error + Warning + Info + Success) - use for troubleshooting
    Note: Requires reboot to take effect. High levels may generate significant event log volume.

.PARAMETER EnableOcspStapling
    Enable OCSP (Online Certificate Status Protocol) stapling for SNI bindings.
    Default: Not configured (disabled for SNI/CCS, enabled for simple bindings)

    Benefits:
    - Reduces OCSP server load by caching responses
    - Improves TLS handshake performance for simple SSL/TLS bindings

    Considerations:
    - May cause performance issues on servers with many SNI certificates
    - Monitor IIS/application performance after enabling

    Reference: https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

.PARAMETER DisableSessionCache
    Disable TLS session caching for maximum security (high-security mode).
    Default: $false (session caching enabled with 10-hour timeout)

    When enabled:
    - Sets ClientCacheTime = 0 (disables client-side session cache)
    - Sets ServerCacheTime = 0 (disables server-side session cache)
    - Prevents session resumption attacks
    - Forces full TLS handshake for every connection
    - Reduces performance but increases security

    Use case: Environments requiring maximum security with no session reuse
    Reference: https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

.PARAMETER MaximumCacheSize
    Maximum number of TLS session cache elements (server-side).
    Default: 20,000 elements
    Valid range: 0-100,000
    Memory usage: Each element uses 2-4KB (~40-80MB for 20,000 elements)

    Set to 0: Disables server-side session cache (similar to -DisableSessionCache)
    Higher values: More memory usage but better performance for high-traffic servers

    Note: Only applies when -DisableSessionCache is NOT used
    Reference: https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

.PARAMETER SendTrustedIssuerList
    Send list of trusted Certificate Authorities to clients during TLS handshake.
    Default: $false (don't send list - secure default on Server 2012+)

    When enabled ($true):
    - Server sends trusted CA list in TLS handshake
    - Helps clients select appropriate certificate for mutual TLS authentication
    - May leak information about your PKI infrastructure

    When disabled ($false):
    - Server does not send trusted CA list (security through obscurity)
    - Client must know which certificate to present

    Reference: https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

.PARAMETER EnableCipherSuiteOrder
    Configure Windows cipher suite ordering to prioritize Perfect Forward Secrecy (PFS) suites.
    Default: $false (don't modify cipher suite order)

    When enabled ($true):
    - Configures cipher suite order following SSL Labs best practices
    - Prioritizes ECDHE suites with AES-GCM (AEAD mode)
    - Ensures server controls cipher suite selection, not client
    - Removes weak/deprecated suites from the list

    Benefits:
    - Perfect Forward Secrecy (protects past sessions if key compromised)
    - Modern AEAD ciphers (GCM, CHACHA20-POLY1305)
    - Optimized performance with hardware-accelerated AES

    Note: This uses Set-TlsCipherSuiteOrder cmdlet (Windows Server 2012 R2+)
    Reference: https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices

.PARAMETER BackupPath
    Directory path for registry backup files.
    Default: $env:TEMP
    Backup files:
    - SchannelBackup_<timestamp>.reg (registry export)
    - SchannelHardening_<timestamp>.log (detailed log)

.PARAMETER Force
    Bypass Windows Server 2008/2008 R2 version blocking.
    Default: $false

    WARNING: NOT RECOMMENDED
    - Server 2008/2008 R2 are End of Life (January 14, 2020)
    - Limited TLS 1.2 support, no TLS 1.3
    - May break system or cause security issues
    - Use only for testing or legacy compatibility

.EXAMPLE
    .\Harden-SchannelSecurity-MS.ps1 -WhatIf
    Preview all changes without applying them.

.EXAMPLE
    .\Harden-SchannelSecurity-MS.ps1 -Confirm:$false
    Apply hardening without confirmation prompts.

.EXAMPLE
    .\Harden-SchannelSecurity-MS.ps1 -MinDhKeyBits 3072
    Use 3072-bit minimum key length for DH/ECDH/RSA (high-security).

.EXAMPLE
    .\Harden-SchannelSecurity-MS.ps1 -EventLogging 7
    Enable maximum event logging for troubleshooting TLS issues.

.EXAMPLE
    .\Harden-SchannelSecurity-MS.ps1 -EnableOcspStapling
    Enable OCSP stapling for improved TLS handshake performance.

.EXAMPLE
    .\Harden-SchannelSecurity-MS.ps1 -DisableSessionCache
    Disable TLS session caching for maximum security (reduces performance).

.EXAMPLE
    .\Harden-SchannelSecurity-MS.ps1 -MinDhKeyBits 3072 -EventLogging 7 -EnableOcspStapling
    High-security configuration with verbose logging and OCSP stapling.

.EXAMPLE
    .\Harden-SchannelSecurity-MS.ps1 -EnableCipherSuiteOrder
    Apply hardening with optimized cipher suite ordering for Perfect Forward Secrecy.

.EXAMPLE
    .\Harden-SchannelSecurity-MS.ps1 -EnableCipherSuiteOrder -MinDhKeyBits 3072 -DisableSessionCache
    Maximum security configuration with PFS cipher ordering, 3072-bit keys, and no session caching.

.NOTES
    Author:         Karol Kula (cquresphere)
    Version:        3.1.1
    Last Updated:   2026-01-22
    Tested On:      Windows Server 2012, 2012 R2, 2016, 2019, 2022

    References:
    - Microsoft TLS Registry Settings: https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
    - Microsoft Manage TLS: https://learn.microsoft.com/en-us/windows-server/security/tls/manage-tls
    - Cipher Suites in Schannel: https://learn.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel
    - SSL Labs Best Practices: https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
    - RFC 7507 TLS Fallback SCSV: https://tools.ietf.org/html/rfc7507
    - CVE-2009-3555 Renegotiation Attack: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3555

    Supported Versions:
    - Windows Server 2012 (Build 9200): Minimum supported version
    - Windows Server 2012 R2+ (Build 9600+): Full feature support
    - Windows Server 2008/2008 R2: BLOCKED (End of Life - use -Force to override)

    Requirements:
    - PowerShell 5.1 or later
    - Administrator privileges
    - Reboot required after execution

    Changelog:
    - 3.1.1: Fixed registry backup failing for paths containing spaces (e.g., WinHttp keys under
             "Internet Settings") by adding proper quoting in reg export arguments
    - 3.1.0: Added TLS compression disable (CRIME mitigation), cipher suite ordering (PFS priority),
             ECC curve configuration, application-level security documentation (HSTS, CSP, cookies),
             aligned with SSL Labs best practices
    - 3.0.0: Added PKCS/RSA key length, OCSP stapling, session cache controls, trusted issuer list,
             enhanced EventLogging (0-7), comprehensive documentation with reference links
    - 2.2.0: Added version detection for Server 2008/2012, version-specific settings
    - 2.1.0: Added missing EphemKeyReuseTime for PFS, fixed ShouldProcess warnings
    - 2.0.0: Initial production-tested version with full hardening support

.LINK
    https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

.LINK
    https://learn.microsoft.com/en-us/windows-server/security/tls/manage-tls
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet(1024, 2048, 3072, 4096)]
    [int]$MinDhKeyBits = 2048,

    [int]$WinHttpProtocols = 0,  # 0 = Auto-detect based on OS version

    [Parameter()]
    [ValidateRange(0, 7)]
    [int]$EventLogging = 1,

    [Parameter()]
    [switch]$EnableOcspStapling,

    [Parameter()]
    [switch]$DisableSessionCache,

    [Parameter()]
    [ValidateRange(0, 100000)]
    [int]$MaximumCacheSize = 20000,

    [Parameter()]
    [switch]$SendTrustedIssuerList,

    [Parameter()]
    [switch]$EnableCipherSuiteOrder,

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

function Remove-RegistryValue {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Path,
        [string]$Name,
        [string]$Description
    )

    $current = $null
    try { $current = (Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue).$Name } catch { }

    if ($null -ne $current) {
        if ($PSCmdlet.ShouldProcess("$Path\$Name", "Remove value")) {
            Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            Write-Log "$Description : Removed (was $current)" -Level OK
            $Script:AppliedCount++
        }
    } else {
        Write-Log "$Description : Not set" -Level SKIP
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
    $key = $null

    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regPath, $true)

        if ($null -eq $key) {
            if ($PSCmdlet.ShouldProcess($CipherName, "Create key")) {
                $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($regPath)
            } else {
                Write-Log "Skipped creating key for $CipherName (WhatIf)" -Level SKIP
                $Script:SkippedCount++
                return
            }
        }

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
    } catch {
        Write-Log "Error setting $CipherName : $_" -Level ERROR
    } finally {
        if ($null -ne $key) { $key.Close() }
    }
}
#endregion Registry Helpers

#region Backup
function New-Backup {
    $backupFile = Join-Path $BackupPath "SchannelBackup_$Script:Timestamp.reg"
    Write-Log "Creating backup: $backupFile" -Level INFO

    $regPaths = @(
        'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
        'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework'
        'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework'
        'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
        'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
    )

    $first = $true
    $hadExport = $false

    foreach ($regPath in $regPaths) {
        $temp = [IO.Path]::GetTempFileName()
        $proc = Start-Process -FilePath reg -ArgumentList @('export', "`"$regPath`"", "`"$temp`"", '/y') -NoNewWindow -PassThru -Wait
        if ($proc.ExitCode -ne 0) {
            Write-Log "Backup export failed for $regPath (exit $($proc.ExitCode))" -Level WARN
            Remove-Item $temp -Force -ErrorAction SilentlyContinue
            continue
        }

        if (Test-Path $temp) {
            $content = Get-Content $temp -ErrorAction SilentlyContinue
            if (-not $first) {
                $content = $content | Where-Object { $_ -notmatch '^Windows Registry Editor Version' }
            }
            if ($content) {
                Add-Content $backupFile -Value $content
                $first = $false
                $hadExport = $true
            }
            Remove-Item $temp -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log "Backup export temp missing for $regPath" -Level WARN
        }
    }

    if (-not $hadExport) {
        Write-Log "Backup failed: no registry data exported" -Level ERROR
    } else {
        Write-Log "Backup created" -Level OK
    }
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

    # Disable TLS compression (CRIME attack mitigation)
    # Reference: https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
    Set-RegistryValue -Path $Script:SchannelBase -Name 'DisableCompression' -Value 1 -Description "DisableCompression (CRIME mitigation)"

    # Event logging (0-7 scale)
    # 0=None, 1=Error, 2=Warn, 3=Error+Warn, 4=Info+Success, 5=Error+Info+Success, 6=Warn+Info+Success, 7=All
    Set-RegistryValue -Path $Script:SchannelBase -Name 'EventLogging' -Value $EventLogging -Description "EventLogging"

    $logDesc = switch ($EventLogging) {
        0 { "No events" }
        1 { "Error events only" }
        2 { "Warning events only" }
        3 { "Error + Warning" }
        4 { "Info + Success" }
        5 { "Error + Info + Success" }
        6 { "Warning + Info + Success" }
        7 { "All events" }
    }
    Write-Log "Event logging level $EventLogging`: $logDesc" -Level INFO
}
#endregion Schannel Base Settings

#region OCSP Stapling
function Set-OcspStapling {
    <#
    .SYNOPSIS
        Configures OCSP (Online Certificate Status Protocol) stapling for SNI.
        Reference: https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

    .DESCRIPTION
        OCSP stapling improves TLS handshake performance by having the server cache and provide
        OCSP responses during the handshake, reducing client OCSP queries.

        Benefits:
        - Reduces OCSP server load
        - Improves TLS handshake performance for simple SSL/TLS bindings

        Considerations:
        - May cause performance issues on servers with many SNI certificates
        - Default: Enabled for simple bindings, Disabled for SNI/CCS bindings
    #>
    Write-Log ""
    Write-Log "=== OCSP STAPLING ===" -Level INFO

    if ($EnableOcspStapling) {
        Write-Log "Enabling OCSP Stapling for SNI" -Level INFO
        Write-Log "IMPORTANT: This may impact performance on servers with many SNI certificates" -Level WARN
        Write-Log "Monitor IIS performance after enabling this feature" -Level WARN
        Set-RegistryValue -Path $Script:SchannelBase -Name 'EnableOcspStaplingForSni' -Value 1 -Description "EnableOcspStaplingForSni"
    } else {
        Write-Log "OCSP Stapling: Not configured (use -EnableOcspStapling to enable)" -Level INFO
        Write-Log "Note: Already enabled by default for simple SSL/TLS bindings (IIS)" -Level INFO
    }
}
#endregion OCSP Stapling

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
        Set-RegistryValue -Path $path -Name 'Enabled' -Value 0xFFFFFFFF -Description "$hash Enabled"
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

    # PKCS/RSA - ClientMinKeyBitLength added in v3.0.0 (was missing in previous versions)
    Write-Log "Configuring PKCS/RSA (ClientMinKeyBitLength=$MinDhKeyBits)" -Level INFO
    $pkcsPath = "$Script:SchannelBase\KeyExchangeAlgorithms\PKCS"
    Set-RegistryValue -Path $pkcsPath -Name 'Enabled' -Value 0xFFFFFFFF -Description "PKCS Enabled"
    Set-RegistryValue -Path $pkcsPath -Name 'ClientMinKeyBitLength' -Value $MinDhKeyBits -Description "PKCS/RSA ClientMinKeyBitLength"
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

#region Session Cache Configuration
function Set-SessionCache {
    <#
    .SYNOPSIS
        Configures TLS session cache settings for performance or security optimization.
        Reference: https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

    .DESCRIPTION
        Session caching allows TLS session resumption, improving performance but storing session data.

        Default behavior:
        - ClientCacheTime: 10 hours
        - ServerCacheTime: 10 hours
        - MaximumCacheSize: 20,000 elements (~40-80MB memory at 2-4KB per element)

        High-security mode (-DisableSessionCache):
        - Disables session resumption (ClientCacheTime = 0, ServerCacheTime = 0)
        - Prevents potential session resumption attacks
        - Reduces performance (full handshake for every connection)
    #>
    Write-Log ""
    Write-Log "=== SESSION CACHE ===" -Level INFO

    if ($DisableSessionCache) {
        Write-Log "Disabling TLS session cache (high-security mode)" -Level WARN
        Set-RegistryValue -Path $Script:SchannelBase -Name 'ClientCacheTime' -Value 0 -Description "ClientCacheTime (disabled)"
        Set-RegistryValue -Path $Script:SchannelBase -Name 'ServerCacheTime' -Value 0 -Description "ServerCacheTime (disabled)"
        Write-Log "WARNING: This will reduce performance but increases security" -Level WARN
        Write-Log "Every TLS connection will require a full handshake" -Level WARN
    } else {
        Write-Log "Session cache: Using system defaults (10 hours)" -Level INFO
        Set-RegistryValue -Path $Script:SchannelBase -Name 'MaximumCacheSize' -Value $MaximumCacheSize -Description "MaximumCacheSize"

        $cacheProps = Get-ItemProperty -Path $Script:SchannelBase -ErrorAction SilentlyContinue
        if ($null -ne $cacheProps) {
            if ($cacheProps.ClientCacheTime -eq 0) {
                Remove-RegistryValue -Path $Script:SchannelBase -Name 'ClientCacheTime' -Description "ClientCacheTime (restore default)"
            }
            if ($cacheProps.ServerCacheTime -eq 0) {
                Remove-RegistryValue -Path $Script:SchannelBase -Name 'ServerCacheTime' -Description "ServerCacheTime (restore default)"
            }
        }

        $memoryMB = [math]::Round($MaximumCacheSize * 3 / 1024, 1)
        Write-Log "Cache capacity: $MaximumCacheSize sessions (~$memoryMB MB memory)" -Level INFO
    }
}
#endregion Session Cache Configuration

#region Trusted Issuer List Configuration
function Set-TrustedIssuerList {
    <#
    .SYNOPSIS
        Configures whether to send the trusted issuer list to TLS clients.
        Reference: https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

    .DESCRIPTION
        Controls SendTrustedIssuerList registry setting.

        When enabled (1):
        - Server sends list of trusted Certificate Authorities to clients during TLS handshake
        - Helps clients select appropriate certificate for authentication
        - May leak information about your PKI infrastructure

        When disabled (0 - default on Server 2012+):
        - Server does not send trusted CA list
        - Better security through obscurity
        - Client must know which certificate to present
    #>
    Write-Log ""
    Write-Log "=== TRUSTED ISSUER LIST ===" -Level INFO

    $value = if ($SendTrustedIssuerList) { 1 } else { 0 }
    Set-RegistryValue -Path $Script:SchannelBase -Name 'SendTrustedIssuerList' -Value $value -Description "SendTrustedIssuerList"

    if ($SendTrustedIssuerList) {
        Write-Log "Sending trusted CA list to clients during TLS handshake" -Level INFO
        Write-Log "WARNING: This may leak PKI infrastructure information" -Level WARN
    } else {
        Write-Log "Trusted CA list: Not sent to clients (default secure behavior)" -Level INFO
    }
}
#endregion Trusted Issuer List Configuration

#region WinHTTP Configuration
function Set-WinHttp {
    Write-Log ""
    Write-Log "=== WINHTTP ===" -Level INFO

    # Auto-detect WinHTTP protocol value if not specified
    $actualProtocols = if ($WinHttpProtocols -eq 0) {
        if ($Script:OsBuild -ge 19042) {
            # Server 2022+ / Win10 20H2+: TLS 1.2 + 1.3
            0x2800
        } else {
            # Server 2012-2019: TLS 1.2 only
            0x0800
        }
    } else {
        $WinHttpProtocols
    }

    $protoDesc = switch ($actualProtocols) {
        0x0A80 { "TLS 1.0 + 1.1 + 1.2" }
        0x2800 { "TLS 1.2 + 1.3" }
        0x0A00 { "TLS 1.1 + 1.2" }
        0x0800 { "TLS 1.2 only" }
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

#region Cipher Suite Ordering
function Set-CipherSuiteOrder {
    <#
    .SYNOPSIS
        Configures Windows cipher suite ordering for Perfect Forward Secrecy and modern security.
        Reference: https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices

    .DESCRIPTION
        Implements SSL Labs best practices for cipher suite ordering:
        - Prioritizes ECDHE (Perfect Forward Secrecy)
        - Prefers AEAD ciphers (GCM, CHACHA20-POLY1305)
        - Removes weak/deprecated cipher suites
        - Ensures server controls cipher selection, not client

        Windows cipher suite names (Schannel format):
        - TLS_ECDHE_* = Elliptic Curve Diffie-Hellman Ephemeral (PFS)
        - TLS_DHE_* = Diffie-Hellman Ephemeral (PFS fallback)
        - *_AES_*_GCM_* = AES with Galois/Counter Mode (AEAD)
        - *_CHACHA20_POLY1305 = Modern AEAD cipher (Server 2022+/Win10+)

        Order Priority:
        1. TLS 1.3 ciphers (if supported)
        2. ECDHE-ECDSA with GCM
        3. ECDHE-RSA with GCM
        4. ECDHE-ECDSA with CHACHA20
        5. ECDHE-RSA with CHACHA20
        6. DHE-RSA with GCM (legacy client support)
        7. ECDHE with CBC mode (fallback for older clients)

        Excluded:
        - RSA key exchange (no forward secrecy)
        - 3DES, RC4, NULL, DES, export ciphers
        - MD5, SHA1 for signatures
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Log ""
    Write-Log "=== CIPHER SUITE ORDERING ===" -Level INFO

    if (-not (Get-Command Get-TlsCipherSuite -ErrorAction SilentlyContinue)) {
        Write-Log "Get-TlsCipherSuite cmdlet not available (requires Server 2012 R2+)" -Level WARN
        return
    }

    # Define optimal cipher suite order following SSL Labs best practices
    # TLS 1.3 cipher suites (Server 2022+/Win10 20H2+)
    $tls13Suites = @(
        'TLS_AES_256_GCM_SHA384'
        'TLS_AES_128_GCM_SHA256'
        'TLS_CHACHA20_POLY1305_SHA256'
    )

    # TLS 1.2 cipher suites with Perfect Forward Secrecy
    $tls12SuitesPriority = @(
        # ECDHE-ECDSA with GCM (best: PFS + AEAD + ECDSA performance)
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'

        # ECDHE-RSA with GCM (PFS + AEAD)
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'

        # ECDHE with CHACHA20-POLY1305 (mobile/embedded devices)
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'
        'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'

        # DHE-RSA with GCM (PFS fallback for systems without ECDHE)
        'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'
        'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'

        # ECDHE with CBC mode (legacy client compatibility - still has PFS)
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384'
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256'
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'

        # DHE with CBC mode (legacy compatibility)
        'TLS_DHE_RSA_WITH_AES_256_CBC_SHA'
        'TLS_DHE_RSA_WITH_AES_128_CBC_SHA'
    )

    # Combine TLS 1.3 and TLS 1.2 suites
    $optimalOrder = $tls13Suites + $tls12SuitesPriority

    # Get currently available cipher suites on this system
    $availableSuites = Get-TlsCipherSuite
    $systemSuiteNames = $availableSuites.Name

    # Filter optimal order to only include suites available on this system
    $finalOrder = $optimalOrder | Where-Object { $_ -in $systemSuiteNames }

    if ($finalOrder.Count -eq 0) {
        Write-Log "No optimal cipher suites found on this system" -Level ERROR
        return
    }

    Write-Log "Optimal cipher suite order (PFS priority):" -Level INFO
    Write-Log "  TLS 1.3 suites: $($tls13Suites.Count) defined" -Level INFO
    Write-Log "  TLS 1.2 suites: $($tls12SuitesPriority.Count) defined" -Level INFO
    Write-Log "  Available on system: $($finalOrder.Count) of $($optimalOrder.Count)" -Level INFO
    Write-Log "" -Level INFO

    # Display proposed order
    Write-Log "Proposed cipher suite order (top 10):" -Level INFO
    $finalOrder | Select-Object -First 10 | ForEach-Object { Write-Log "  $_" -Level INFO }
    if ($finalOrder.Count -gt 10) {
        Write-Log "  ... and $($finalOrder.Count - 10) more" -Level INFO
    }

    if ($PSCmdlet.ShouldProcess("Cipher Suite Order", "Configure $($finalOrder.Count) suites")) {
        try {
            # Set the cipher suite order
            # Note: This cmdlet is available on Server 2012 R2+ and Win8.1+
            $suiteString = $finalOrder -join ','
            Enable-TlsCipherSuite -Name $finalOrder[0] -Position 0 -ErrorAction Stop | Out-Null

            # Set complete order using registry (more reliable than cmdlet for bulk operations)
            $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }

            Set-ItemProperty -Path $regPath -Name 'Functions' -Value $suiteString -Type MultiString -ErrorAction Stop
            Write-Log "Cipher suite order configured successfully" -Level OK
            Write-Log "Server will now prioritize PFS-enabled cipher suites" -Level OK
            $Script:AppliedCount++
        } catch {
            Write-Log "Failed to set cipher suite order: $_" -Level ERROR
            Write-Log "Note: Requires Windows Server 2012 R2+ or Windows 8.1+" -Level WARN
        }
    }
}
#endregion Cipher Suite Ordering

#region ECC Curve Configuration
function Set-EccCurves {
    <#
    .SYNOPSIS
        Configures elliptic curve priority for ECDHE key exchange.
        Reference: https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices

    .DESCRIPTION
        Sets ECC curve priority following SSL Labs recommendations:
        - P-384 (secp384r1): 192-bit security, recommended for high-security environments
        - P-256 (secp256r1): 128-bit security, most widely supported, good performance
        - curve25519: Modern curve with excellent security and performance (Server 2022+)

        Excluded curves:
        - P-521: Offers diminishing returns, slower performance
        - P-192, P-224: Insufficient security for modern standards

        Note: This configuration only applies to Server 2016+ and Win10+
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-Log ""
    Write-Log "=== ECC CURVE CONFIGURATION ===" -Level INFO

    # ECC curve configuration only available on Server 2016+ (Build 14393+)
    if ($Script:OsBuild -lt 14393) {
        Write-Log "ECC curve configuration: Not supported (requires Server 2016+, current: Build $Script:OsBuild)" -Level INFO
        return
    }

    # Define optimal curve order
    # Windows curve names: NistP384, NistP256, curve25519 (Server 2022+)
    $optimalCurves = @(
        'NistP384'  # secp384r1 - 192-bit security
        'NistP256'  # secp256r1 - 128-bit security (SSL Labs recommended)
    )

    # Add curve25519 for Server 2022+ (Build 20348+)
    if ($Script:OsBuild -ge 20348) {
        $optimalCurves += 'curve25519'
    }

    Write-Log "Configuring ECC curve priority:" -Level INFO
    foreach ($curve in $optimalCurves) {
        Write-Log "  Priority: $curve" -Level INFO
    }

    if ($PSCmdlet.ShouldProcess("ECC Curves", "Configure priority order")) {
        try {
            $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }

            $curveString = $optimalCurves -join ' '
            Set-ItemProperty -Path $regPath -Name 'EccCurves' -Value $curveString -Type MultiString -ErrorAction Stop
            Write-Log "ECC curve priority configured successfully" -Level OK
            $Script:AppliedCount++
        } catch {
            Write-Log "Failed to set ECC curve priority: $_" -Level ERROR
        }
    }
}
#endregion ECC Curve Configuration

#region Main
function Invoke-Hardening {
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "   SCHANNEL SECURITY HARDENING - PRODUCTION TESTED v3.1.1" -ForegroundColor Cyan
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
    Write-Log "  Min Key Bits (DH/ECDH/RSA): $MinDhKeyBits" -Level INFO
    Write-Log "  Event Logging Level: $EventLogging" -Level INFO
    Write-Log "  OCSP Stapling: $EnableOcspStapling" -Level INFO
    Write-Log "  Session Cache Disabled: $DisableSessionCache" -Level INFO
    if (-not $DisableSessionCache) {
        Write-Log "  Max Cache Size: $MaximumCacheSize elements" -Level INFO
    }
    Write-Log "  Send Trusted Issuer List: $SendTrustedIssuerList" -Level INFO
    Write-Log "  Cipher Suite Ordering: $EnableCipherSuiteOrder" -Level INFO

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
    Set-OcspStapling
    Set-Protocols
    Set-Ciphers
    Set-Hashes
    Set-KeyExchange
    Set-EccCurves
    Set-DotNetFramework
    Set-SessionCache
    Set-TrustedIssuerList
    Set-WinHttp
    Disable-NullCipherSuites

    # Cipher suite ordering (optional, requires explicit parameter)
    if ($EnableCipherSuiteOrder) {
        Set-CipherSuiteOrder
    } else {
        Write-Log ""
        Write-Log "=== CIPHER SUITE ORDERING ===" -Level INFO
        Write-Log "Cipher suite ordering: Not configured (use -EnableCipherSuiteOrder to enable)" -Level INFO
        Write-Log "Note: Enabling this prioritizes Perfect Forward Secrecy (PFS) cipher suites" -Level INFO
    }

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

    # Application-level security reminders
    Write-Log "IMPORTANT: APPLICATION-LEVEL SECURITY CONFIGURATION REQUIRED" -Level WARN
    Write-Log "This script configures OS-level TLS/SSL settings only." -Level WARN
    Write-Log "You must also configure the following at the web server/application level:" -Level WARN
    Write-Log "" -Level INFO
    Write-Log "  1. HTTP Strict Transport Security (HSTS) - CRITICAL" -Level WARN
    Write-Log "     Header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" -Level INFO
    Write-Log "     Configure in: IIS, Apache, Nginx, or application code" -Level INFO
    Write-Log "" -Level INFO
    Write-Log "  2. Secure Cookies - Mark all cookies with Secure and HttpOnly flags" -Level WARN
    Write-Log "  3. Content Security Policy (CSP) - Prevent XSS and mixed content" -Level WARN
    Write-Log "  4. Certificate Configuration - Use proper certificate chains and OCSP stapling" -Level WARN
    Write-Log "  5. DNS CAA Records - Restrict which CAs can issue certificates" -Level WARN
    Write-Log "" -Level INFO
    Write-Log "Reference: https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices" -Level INFO
    Write-Log ""

    if ($Script:OsBuild -eq 9200) {
        Write-Log "SERVER 2012 POST-HARDENING NOTES:" -Level WARN
        Write-Log "  1. TLS 1.0/1.1 remains enabled for compatibility" -Level WARN
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
