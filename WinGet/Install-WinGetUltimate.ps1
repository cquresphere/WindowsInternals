<#
.SYNOPSIS
    Ultimate WinGet installer and source-repair utility.

.DESCRIPTION
    Comprehensive script that handles:
    - Admin privilege verification
    - Execution-context detection (SYSTEM vs. interactive admin)
    - OS compatibility checks
    - Visual C++ Redistributable installation
    - WinGet dependencies (VCLibs, UI.Xaml)
    - WinGet installation via multiple fallback methods:
        1. Repair-WinGetPackageManager (Microsoft.WinGet.Client module)
        2. Direct download from GitHub releases with license provisioning
        3. aka.ms/getwinget shortcut download
    - Supported-platform enforcement:
        - Windows 10 1809+, Windows 11 and Windows Server 2025+
        - Windows Server 2019/2022 only through an explicit, unsupported
          portable-extraction mode
    - Functional (not merely presence-based) winget detection
    - Repair of the "provisioned but not registered" state that produces
      ApplicationFailedException / Win32 1920 (ERROR_CANT_ACCESS_FILE)
    - Non-interactive source-agreement handling (fixes 0x8a150042)
    - Per-source health checks for winget and msstore
    - WinGet Source MSIX registration (fixes 0x8a15000f)
    - Default-source repair without deleting custom sources
    - Safe, process-local PATH configuration

.PARAMETER Force
    Enables repair actions that change state. This includes accepting the
    Microsoft source agreements for the current execution identity, resetting
    only the built-in winget/msstore sources, repairing the source package and,
    if those steps fail, reinstalling WinGet.

.PARAMETER AcceptSourceAgreements
    Accepts WinGet source agreements non-interactively for the current execution
    identity. Use this when WinGet itself is healthy and only error 0x8a150042
    must be resolved. -Force implies -AcceptSourceAgreements.

.PARAMETER SkipSourceFix
    Skips the WinGet Source MSIX registration step.

.PARAMETER ExperimentalPortableServer
    Explicitly enables the unsupported portable WinGet extraction method on
    Windows Server 2019 or 2022 with Desktop Experience. The packaged App
    Installer route is not used, the Microsoft Store source is not validated,
    and the extracted client is installed under Program Files\WinGetPortable.
    This mode is not available on Server Core.

.PARAMETER Verbose
    Enables detailed output for troubleshooting.

.EXAMPLE
    .\Install-WinGetUltimate.ps1
    # Standard installation

.EXAMPLE
    .\Install-WinGetUltimate.ps1 -Force
    # Accept source agreements and run the complete repair sequence

.EXAMPLE
    .\Install-WinGetUltimate.ps1 -AcceptSourceAgreements
    # Accept and validate source agreements without destructive source reset

.EXAMPLE
    .\Install-WinGetUltimate.ps1 -Force -Verbose
    # Complete repair with detailed output

.EXAMPLE
    .\Install-WinGetUltimate.ps1 -Force -ExperimentalPortableServer -Verbose
    # Unsupported portable mode for Windows Server 2019/2022 Desktop Experience

.NOTES
    Version : 2.1.1
    Author  : Karol Kula
    Requires: Administrator privileges; Windows 10 1809+, Windows 11, or
              Windows Server 2025+. Server 2019/2022 are experimental only.

    v1.1.0 - Detection layer rewritten.
             winget.exe is never invoked as a bare native command. The App
             Execution Alias in %LOCALAPPDATA%\Microsoft\WindowsApps is a
             zero-byte reparse stub that exists even when the MSIX package is
             not registered for the calling identity; invoking it raises a
             NativeCommandFailed / ApplicationFailedException that 2>$null
             does not suppress and that $ErrorActionPreference='Stop' turns
             into a script-terminating error.

    v2.0.0 - Adds explicit, non-interactive source agreement acceptance and
             source repair. -Force now uses the least-disruptive successful
             repair path before falling back to package reinstallation.

    v2.1.0 - Corrects Windows Server support detection, adds opt-in portable
             extraction for Server 2019/2022 Desktop Experience, consumes the
             dependency bundle published with the selected WinGet release,
             and stops misdiagnosing unsupported packaged execution as an ACL
             problem.

    v2.1.1 - Reports the unpackaged client's actual diagnostic log directory
             (%TEMP%\WinGet\defaultState) in portable-server mode.
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [switch]$Force,
    [switch]$AcceptSourceAgreements,
    [switch]$SkipSourceFix,
    [switch]$ExperimentalPortableServer
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ConfirmPreference = 'None'

$script:WinGetFamilyName  = 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe'
$script:WinGetPackageName = 'Microsoft.DesktopAppInstaller'
$script:AcceptAgreements  = [bool]($Force -or $AcceptSourceAgreements)
$script:PortableRoot      = Join-Path $env:ProgramFiles 'WinGetPortable'
$script:UsePortableMode   = $false

# ============================================================================ #
#  Helper Functions
# ============================================================================ #

function Write-Step {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "[..] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function New-TempFolder {
    <#
    .SYNOPSIS
        Creates a temporary folder for downloads and returns its path.
    #>
    $folderName = "WinGet_Install_" + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $tempPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath $folderName
    New-Item -Path $tempPath -ItemType Directory -Force | Out-Null
    return $tempPath
}

function Remove-TempFolder {
    param([string]$Path)
    if ($Path -and (Test-Path -Path $Path)) {
        Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Test-AdminPrivileges {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsSystemContext {
    <#
    .SYNOPSIS
        Returns $true when running as LocalSystem (S-1-5-18).
    .DESCRIPTION
        App Execution Aliases are a per-user MSIX construct and never resolve
        under SYSTEM. Intune platform scripts, ConfigMgr and PsExec all land
        here, so the alias path must be excluded and winget.exe invoked from
        its WindowsApps package folder directly.
    #>
    try {
        return ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
    } catch {
        return $false
    }
}

function ConvertTo-SafeVersion {
    <#
    .SYNOPSIS
        Best-effort [version] conversion; returns 0.0.0.0 on failure so that
        Sort-Object never throws on a malformed package folder name.
    #>
    param([string]$InputString)
    $v = $null
    if ([version]::TryParse($InputString, [ref]$v)) { return $v }
    return [version]'0.0.0.0'
}

function Get-WinGetLaunchDiagnosis {
    <#
    .SYNOPSIS
        Maps a Win32 error code from a failed CreateProcess into an actionable cause.
    #>
    param([int]$NativeErrorCode)

    switch ($NativeErrorCode) {
        1920   { 'ERROR_CANT_ACCESS_FILE (1920) - the App Execution Alias resolved to a package that is NOT registered for the calling identity. Typical on Server SKUs, freshly provisioned packages and SYSTEM context.' }
        2      { 'ERROR_FILE_NOT_FOUND (2) - the alias points at a DesktopAppInstaller version that has been removed or upgraded away.' }
        5      { 'ERROR_ACCESS_DENIED (5) - execution was denied. On Windows Server 2019/2022, packaged WinGet is unsupported and the App Execution Alias extension is unavailable; on supported systems, investigate AppLocker, WDAC and package registration before considering ACLs.' }
        216    { 'ERROR_EXE_MACHINE_TYPE_MISMATCH (216) - architecture mismatch (e.g. x64 binary on ARM64 without emulation).' }
        740    { 'ERROR_ELEVATION_REQUIRED (740) - the process requires elevation.' }
        default { "Win32 error $NativeErrorCode." }
    }
}

function Invoke-WinGetProcess {
    <#
    .SYNOPSIS
        Invokes winget.exe out-of-process without ever using PowerShell's native
        command operator.
    .DESCRIPTION
        The call operator (&) surfaces a failed CreateProcess as a
        NativeCommandFailed / ApplicationFailedException error record. That
        record is NOT stderr, so 2>$null does not suppress it, and under
        $ErrorActionPreference = 'Stop' it terminates the script.

        System.Diagnostics.Process throws a catchable Win32Exception instead,
        and exposes NativeErrorCode, which is what actually identifies the
        failure mode (1920 vs 5 vs 2).
    .OUTPUTS
        PSCustomObject with Ran, ExitCode, StdOut, StdErr, NativeErrorCode, ErrorMessage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 120
    )

    $result = [PSCustomObject]@{
        Ran             = $false
        ExitCode        = $null
        StdOut          = ''
        StdErr          = ''
        NativeErrorCode = $null
        ErrorMessage    = $null
        TimedOut        = $false
    }

    if (-not (Test-Path -LiteralPath $ExePath)) {
        $result.ErrorMessage = "Path does not exist: $ExePath"
        return $result
    }

    $quoted = $Arguments | ForEach-Object {
        if ($_ -match '\s') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $ExePath
    $psi.Arguments              = ($quoted -join ' ')
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    # winget emits UTF-8; without this the console codepage mangles output on
    # non-English systems (and breaks any downstream string matching).
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding  = [System.Text.Encoding]::UTF8

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    try {
        [void]$proc.Start()
    } catch [System.ComponentModel.Win32Exception] {
        $result.NativeErrorCode = $_.Exception.NativeErrorCode
        $result.ErrorMessage    = Get-WinGetLaunchDiagnosis -NativeErrorCode $_.Exception.NativeErrorCode
        $proc.Dispose()
        return $result
    } catch {
        $result.ErrorMessage = $_.Exception.Message
        $proc.Dispose()
        return $result
    }

    # Read asynchronously before WaitForExit to avoid the classic pipe-buffer deadlock.
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()

    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
        try { $proc.Kill() } catch { }
        $result.TimedOut     = $true
        $result.ErrorMessage = "winget.exe did not exit within $TimeoutSeconds seconds."
        $proc.Dispose()
        return $result
    }

    try { $result.StdOut = $outTask.GetAwaiter().GetResult() } catch { }
    try { $result.StdErr = $errTask.GetAwaiter().GetResult() } catch { }

    $result.Ran      = $true
    $result.ExitCode = $proc.ExitCode
    $proc.Dispose()
    return $result
}

function Get-LatestStableWinGetRelease {
    <# Returns the latest non-preview release metadata from the official repository. #>
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    return Invoke-RestMethod `
        -Uri 'https://api.github.com/repos/microsoft/winget-cli/releases/latest' `
        -Headers @{ 'User-Agent' = 'Install-WinGetUltimate' } `
        -Method Get `
        -ErrorAction Stop
}

function Get-WinGetPortablePackage {
    <# Resolves the stable junction created by experimental portable mode. #>
    $currentPath = Join-Path $script:PortableRoot 'current'
    $exePath = Join-Path $currentPath 'winget.exe'
    if (-not (Test-Path -LiteralPath $exePath)) { return $null }

    $version = 'Portable'
    $versionFile = Join-Path $currentPath 'portable-release.txt'
    if (Test-Path -LiteralPath $versionFile) {
        $version = (Get-Content -LiteralPath $versionFile -Raw -ErrorAction SilentlyContinue).Trim()
    }

    return [PSCustomObject]@{
        Source          = 'Portable'
        Version         = $version
        InstallLocation = $currentPath
        ExePath         = $exePath
        ManifestPath    = $null
        PackageFullName = $null
    }
}

function Add-WinGetPortableToPath {
    <# Adds only the stable portable junction, never a versioned WindowsApps path. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $entries = @($machinePath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if (-not ($entries | Where-Object { $_.TrimEnd('\') -ieq $Path.TrimEnd('\') })) {
        $entries += $Path
        [Environment]::SetEnvironmentVariable('Path', ($entries -join ';'), 'Machine')
    }

    if (-not ($env:Path -split ';' | Where-Object { $_.TrimEnd('\') -ieq $Path.TrimEnd('\') })) {
        $env:Path = "$Path;$env:Path"
    }
}

function Install-WinGetPortableServer {
    <#
    .SYNOPSIS
        Extracts WinGet from the signed App Installer bundle without registering
        the unsupported MSIX package on Windows Server 2019/2022.
    .NOTES
        This is an explicitly unsupported compatibility mode based on the
        extraction method referenced by the WinGet project's own README.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Architecture)

    if ($Architecture -ne 'x64') {
        Write-Warning "Experimental portable server mode has only been validated by this script for x64; detected '$Architecture'."
        return $false
    }

    $tempFolder = New-TempFolder
    try {
        $release = Get-LatestStableWinGetRelease
        $bundleAsset = $release.assets | Where-Object {
            $_.name -eq 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
        } | Select-Object -First 1

        if (-not $bundleAsset) {
            throw 'The latest stable release does not contain the DesktopAppInstaller MSIX bundle.'
        }

        $bundlePath = Join-Path $tempFolder $bundleAsset.name
        Write-Info "Downloading WinGet $($release.tag_name) for portable extraction..."
        Invoke-WebRequest -Uri $bundleAsset.browser_download_url -OutFile $bundlePath -UseBasicParsing -ErrorAction Stop

        $bundleSignature = Get-AuthenticodeSignature -FilePath $bundlePath
        if ($bundleSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "The App Installer bundle signature is not valid: $($bundleSignature.Status)."
        }

        $bundleZip = Join-Path $tempFolder 'DesktopAppInstaller.zip'
        Copy-Item -LiteralPath $bundlePath -Destination $bundleZip -Force
        $bundleExtract = Join-Path $tempFolder 'Bundle'
        Expand-Archive -LiteralPath $bundleZip -DestinationPath $bundleExtract -Force

        $innerPackage = Get-ChildItem -LiteralPath $bundleExtract -File `
            -Filter "AppInstaller_$Architecture.msix" -ErrorAction Stop | Select-Object -First 1
        if (-not $innerPackage) {
            throw "The bundle does not contain AppInstaller_$Architecture.msix."
        }

        $innerZip = Join-Path $tempFolder "AppInstaller_$Architecture.zip"
        Copy-Item -LiteralPath $innerPackage.FullName -Destination $innerZip -Force
        $payloadPath = Join-Path $tempFolder 'Payload'
        Expand-Archive -LiteralPath $innerZip -DestinationPath $payloadPath -Force

        $payloadExe = Join-Path $payloadPath 'winget.exe'
        if (-not (Test-Path -LiteralPath $payloadExe)) {
            throw 'winget.exe was not found in the extracted architecture package.'
        }

        $releaseName = ([string]$release.tag_name).TrimStart('v')
        if ([string]::IsNullOrWhiteSpace($releaseName)) {
            $releaseName = (Get-Date -Format 'yyyyMMddHHmmss')
        }

        New-Item -Path $script:PortableRoot -ItemType Directory -Force | Out-Null
        $versionPath = Join-Path $script:PortableRoot $releaseName

        if ((Test-Path -LiteralPath $versionPath) -and
            -not (Test-Path -LiteralPath (Join-Path $versionPath 'winget.exe'))) {
            $versionPath = Join-Path $script:PortableRoot ("{0}-{1}" -f $releaseName, (Get-Date -Format 'yyyyMMddHHmmss'))
        }

        if (-not (Test-Path -LiteralPath $versionPath)) {
            New-Item -Path $versionPath -ItemType Directory -Force | Out-Null
            Get-ChildItem -LiteralPath $payloadPath -Force |
                Copy-Item -Destination $versionPath -Recurse -Force
            $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
            [IO.File]::WriteAllText(
                (Join-Path $versionPath 'portable-release.txt'),
                $release.tag_name,
                $utf8NoBom
            )
        }

        $currentPath = Join-Path $script:PortableRoot 'current'
        $currentItem = Get-Item -LiteralPath $currentPath -Force -ErrorAction SilentlyContinue
        if ($currentItem) {
            if (($currentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Remove-Item -LiteralPath $currentPath -Force
            } else {
                $backupPath = Join-Path $script:PortableRoot ("current-backup-{0}" -f (Get-Date -Format 'yyyyMMddHHmmss'))
                Move-Item -LiteralPath $currentPath -Destination $backupPath -Force
            }
        }

        New-Item -Path $currentPath -ItemType Junction -Target $versionPath -Force | Out-Null
        Add-WinGetPortableToPath -Path $currentPath

        $run = Invoke-WinGetProcess -ExePath (Join-Path $currentPath 'winget.exe') `
                                    -Arguments @('--version') -TimeoutSeconds 60
        if (-not ($run.Ran -and $run.ExitCode -eq 0)) {
            throw "The extracted WinGet client did not start: $($run.ErrorMessage) $($run.StdErr)"
        }

        Write-Success "Experimental portable WinGet $($run.StdOut.Trim()) is runnable."
        return $true
    } catch {
        Write-Warning "Experimental portable WinGet installation failed: $($_.Exception.Message)"
        return $false
    } finally {
        Remove-TempFolder -Path $tempFolder
    }
}

function Get-WinGetDiagnosticLogPath {
    <# Returns the native WinGet diagnostic directory for this identity. #>
    if ($script:UsePortableMode) {
        if ([string]::IsNullOrWhiteSpace($env:TEMP)) { return $null }
        return (Join-Path $env:TEMP 'WinGet\defaultState')
    }

    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { return $null }
    return (Join-Path $env:LOCALAPPDATA `
        'Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir')
}

function Test-WinGetSourceHealth {
    <#
    .SYNOPSIS
        Opens each built-in package source and returns a structured result.
    .DESCRIPTION
        A source list is not a sufficient test: it enumerates configuration but
        does not necessarily open msstore. The search probes below deliberately
        query known packages so that pending source agreements and backend
        failures are detected. When -AcceptAgreements is supplied, the flag is
        passed to the source-consuming command that can otherwise prompt.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExePath,
        [switch]$AcceptAgreements,
        [switch]$SkipMicrosoftStore
    )

    $definitions = @(
        [PSCustomObject]@{
            Name = 'winget'
            Id   = 'Microsoft.PowerShell'
        }
    )

    if (-not $SkipMicrosoftStore) {
        $definitions += [PSCustomObject]@{
            Name = 'msstore'
            Id   = '9MZ1SNWT0N5D'
        }
    }

    $checks = New-Object System.Collections.Generic.List[object]

    foreach ($definition in $definitions) {
        $arguments = @(
            'search', '--id', $definition.Id, '--exact', '--count', '1',
            '--source', $definition.Name,
            '--disable-interactivity', '--verbose-logs'
        )

        if ($AcceptAgreements) {
            $arguments += '--accept-source-agreements'
        }

        $run = Invoke-WinGetProcess -ExePath $ExePath -Arguments $arguments -TimeoutSeconds 180
        $combined = (@($run.StdOut, $run.StdErr, $run.ErrorMessage) |
                     Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join "`n"

        $checks.Add([PSCustomObject]@{
            Source             = $definition.Name
            Healthy            = [bool]($run.Ran -and $run.ExitCode -eq 0)
            ExitCode           = $run.ExitCode
            AgreementPrompt    = [bool]($combined -match '0x8a150042|Error reading input in prompt|source agreements')
            MissingSourceData  = [bool]($combined -match '0x8a15000f|Data required by the source is missing')
            PolicyBlocked      = [bool]($combined -match '0x8a150011|disabled by policy|Group Policy')
            Output             = $combined.Trim()
        })
    }

    $failed = @($checks | Where-Object { -not $_.Healthy })
    return [PSCustomObject]@{
        Healthy = ($failed.Count -eq 0)
        Checks  = $checks
        LogPath = Get-WinGetDiagnosticLogPath
    }
}

function Install-WinGetSourcePackage {
    <# Installs the official signed source.msix used by the winget source. #>
    [CmdletBinding()]
    param()

    $tempFolder = New-TempFolder
    $sourcePath = Join-Path $tempFolder 'source.msix'

    try {
        Write-Info 'Downloading the official WinGet source package...'
        Invoke-WebRequest -Uri 'https://cdn.winget.microsoft.com/cache/source.msix' `
                          -OutFile $sourcePath -UseBasicParsing -ErrorAction Stop

        $signature = Get-AuthenticodeSignature -FilePath $sourcePath
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "The source.msix signature is not valid: $($signature.Status) - $($signature.StatusMessage)"
        }

        Add-AppxPackage -Path $sourcePath -ErrorAction Stop
        Write-Success 'The signed WinGet source package was installed.'
        return $true
    } catch {
        Write-Warning "WinGet source package installation failed: $($_.Exception.Message)"
        return $false
    } finally {
        Remove-TempFolder -Path $tempFolder
    }
}

function Repair-WinGetSources {
    <#
    .SYNOPSIS
        Accepts agreements and repairs only the built-in sources.
    .NOTES
        Custom sources are intentionally preserved. A global
        `winget source reset --force` would remove them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExePath,
        [switch]$ResetDefaults,
        [switch]$RepairSourcePackage,
        [switch]$SkipMicrosoftStore
    )

    Write-Info 'Accepting and validating WinGet source agreements...'
    $health = Test-WinGetSourceHealth -ExePath $ExePath -AcceptAgreements `
        -SkipMicrosoftStore:$SkipMicrosoftStore
    if ($health.Healthy) { return $health }

    if ($ResetDefaults) {
        $sourcesToReset = @('winget')
        if (-not $SkipMicrosoftStore) { $sourcesToReset += 'msstore' }

        foreach ($sourceName in $sourcesToReset) {
            Write-Info "Resetting built-in source '$sourceName'..."
            $reset = Invoke-WinGetProcess -ExePath $ExePath `
                -Arguments @('source', 'reset', '--name', $sourceName, '--force', '--disable-interactivity', '--verbose-logs') `
                -TimeoutSeconds 180
            if (-not ($reset.Ran -and $reset.ExitCode -eq 0)) {
                Write-Verbose "Reset of '$sourceName' failed: $($reset.StdErr) $($reset.ErrorMessage)"
            }
        }

        # A reset invalidates prior agreement state, so accept it again by
        # opening both sources with source-consuming commands.
        $health = Test-WinGetSourceHealth -ExePath $ExePath -AcceptAgreements `
            -SkipMicrosoftStore:$SkipMicrosoftStore
        if ($health.Healthy) { return $health }
    }

    if ($RepairSourcePackage) {
        if (Install-WinGetSourcePackage) {
            $reset = Invoke-WinGetProcess -ExePath $ExePath `
                -Arguments @('source', 'reset', '--name', 'winget', '--force', '--disable-interactivity', '--verbose-logs') `
                -TimeoutSeconds 180
            Write-Verbose "WinGet source reset exit code: $($reset.ExitCode)"
            $health = Test-WinGetSourceHealth -ExePath $ExePath -AcceptAgreements `
                -SkipMicrosoftStore:$SkipMicrosoftStore
        }
    }

    return $health
}

function Get-WinGetPackage {
    <#
    .SYNOPSIS
        Resolves the highest-version DesktopAppInstaller package and its real
        winget.exe path.
    .DESCRIPTION
        Primary source is the Appx stack (Get-AppxPackage -AllUsers), which
        works under SYSTEM and does not depend on being able to enumerate
        C:\Program Files\WindowsApps - Administrators are denied traversal on
        parts of that tree by default, which is why filesystem globbing is only
        the fallback here.

        Version ordering is done with [version], not lexical Sort-Object Path:
        lexically, "1.9.x" sorts after "1.24.x", which selects the wrong package.
    #>
    [CmdletBinding()]
    param()

    $pkg = $null

    try {
        $pkg = Get-AppxPackage -AllUsers -Name $script:WinGetPackageName -ErrorAction Stop |
               Where-Object { $_.InstallLocation } |
               Sort-Object { ConvertTo-SafeVersion $_.Version } |
               Select-Object -Last 1
    } catch {
        Write-Verbose "Get-AppxPackage -AllUsers failed: $($_.Exception.Message)"
    }

    if (-not $pkg) {
        try {
            $pkg = Get-AppxPackage -Name $script:WinGetPackageName -ErrorAction SilentlyContinue |
                   Where-Object { $_.InstallLocation } |
                   Sort-Object { ConvertTo-SafeVersion $_.Version } |
                   Select-Object -Last 1
        } catch {
            Write-Verbose "Get-AppxPackage failed: $($_.Exception.Message)"
        }
    }

    if ($pkg -and $pkg.InstallLocation) {
        return [PSCustomObject]@{
            Source          = 'AppxPackage'
            Version         = $pkg.Version
            InstallLocation = $pkg.InstallLocation
            ExePath         = Join-Path $pkg.InstallLocation 'winget.exe'
            ManifestPath    = Join-Path $pkg.InstallLocation 'AppXManifest.xml'
            PackageFullName = $pkg.PackageFullName
        }
    }

    # Fallback: enumerate WindowsApps directly.
    $roots = @($env:ProgramFiles, $env:ProgramW6432) |
             Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
             ForEach-Object { Join-Path $_ 'WindowsApps' } |
             Select-Object -Unique

    $candidates = foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -Directory -Filter "$($script:WinGetPackageName)_*__8wekyb3d8bbwe" -ErrorAction SilentlyContinue
    }

    $best = $candidates |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'winget.exe') } |
            Sort-Object { ConvertTo-SafeVersion ($_.Name -split '_')[1] } |
            Select-Object -Last 1

    if ($best) {
        return [PSCustomObject]@{
            Source          = 'FileSystem'
            Version         = ($best.Name -split '_')[1]
            InstallLocation = $best.FullName
            ExePath         = Join-Path $best.FullName 'winget.exe'
            ManifestPath    = Join-Path $best.FullName 'AppXManifest.xml'
            PackageFullName = $best.Name
        }
    }

    return $null
}

function Get-WinGetExePath {
    <#
    .SYNOPSIS
        Returns the folder path of the resolved winget package (back-compat shim).
    #>
    $pkg = Get-WinGetPortablePackage
    if (-not $pkg) { $pkg = Get-WinGetPackage }
    if ($pkg) { return $pkg.InstallLocation }
    return $null
}

function Get-WinGetInstallation {
    <# Returns the active portable installation first, then the packaged client. #>
    $portable = Get-WinGetPortablePackage
    if ($portable) { return $portable }
    return (Get-WinGetPackage)
}

function Test-WinGetExists {
    <#
    .SYNOPSIS
        Tests whether winget binaries exist on disk, regardless of runnability.
    #>
    $pkg = Get-WinGetInstallation
    return ($null -ne $pkg -and (Test-Path -LiteralPath $pkg.ExePath))
}

function Test-WinGetFunctional {
    <#
    .SYNOPSIS
        Determines whether winget can actually be executed, and via which path.
    .DESCRIPTION
        Replaces the old Get-Command probe. Get-Command succeeds on the
        zero-byte App Execution Alias stub, so it reports "installed" on exactly
        the machines that are broken.

        Candidates are tried in order of trustworthiness:
          1. The explicitly installed portable client
          2. The WindowsApps package binary
          3. The per-user App Execution Alias (skipped under SYSTEM)
          4. Whatever is on PATH
    .OUTPUTS
        PSCustomObject: Working, ExePath, Version, Kind, BinaryPresent,
                        FailureReason, NativeErrorCode, Attempts.
    #>
    [CmdletBinding()]
    param([switch]$AllowAlias)

    $isSystem   = Test-IsSystemContext
    $pkg        = Get-WinGetPackage
    $portable   = Get-WinGetPortablePackage
    $candidates = New-Object System.Collections.Generic.List[object]

    if ($portable -and (Test-Path -LiteralPath $portable.ExePath)) {
        $candidates.Add([PSCustomObject]@{ Kind = 'Portable'; Path = $portable.ExePath })
    }

    if ($pkg -and (Test-Path -LiteralPath $pkg.ExePath)) {
        $candidates.Add([PSCustomObject]@{ Kind = 'Package'; Path = $pkg.ExePath })
    }

    if ((-not $isSystem -or $AllowAlias) -and -not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        # $env:LOCALAPPDATA is absent in some service contexts; guard it, because
        # $ErrorActionPreference = 'Stop' would turn a null Join-Path into a
        # terminating error inside the detection routine itself.
        $aliasPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
        if (Test-Path -LiteralPath $aliasPath) {
            $candidates.Add([PSCustomObject]@{ Kind = 'Alias'; Path = $aliasPath })
        }
    } elseif ($isSystem) {
        Write-Verbose 'SYSTEM context detected - App Execution Alias excluded from candidates.'
    }

    $onPath = Get-Command -Name 'winget.exe' -CommandType Application -ErrorAction SilentlyContinue |
              Select-Object -First 1
    if ($onPath) {
        $candidates.Add([PSCustomObject]@{ Kind = 'Path'; Path = $onPath.Source })
    }

    $seen     = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    $attempts = New-Object System.Collections.Generic.List[object]

    $state = [PSCustomObject]@{
        Working         = $false
        ExePath         = $null
        Version         = $null
        Kind            = $null
        BinaryPresent   = ($null -ne $pkg -or $null -ne $portable)
        IsSystemContext = $isSystem
        FailureReason   = $null
        NativeErrorCode = $null
        Attempts        = $attempts
    }

    foreach ($candidate in $candidates) {
        if (-not $seen.Add($candidate.Path)) { continue }

        $run = Invoke-WinGetProcess -ExePath $candidate.Path -Arguments @('--version') -TimeoutSeconds 45
        $attempts.Add([PSCustomObject]@{
            Kind            = $candidate.Kind
            Path            = $candidate.Path
            Ran             = $run.Ran
            ExitCode        = $run.ExitCode
            NativeErrorCode = $run.NativeErrorCode
            Message         = $run.ErrorMessage
        })

        if ($run.Ran -and $run.ExitCode -eq 0) {
            $state.Working = $true
            $state.ExePath = $candidate.Path
            $state.Kind    = $candidate.Kind
            $state.Version = ($run.StdOut -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1).Trim()
            return $state
        }

        Write-Verbose "Candidate [$($candidate.Kind)] '$($candidate.Path)' failed: $($run.ErrorMessage) (exit $($run.ExitCode))"
        if ($null -eq $state.NativeErrorCode -and $null -ne $run.NativeErrorCode) {
            $state.NativeErrorCode = $run.NativeErrorCode
            $state.FailureReason   = $run.ErrorMessage
        }
    }

    if (-not $state.FailureReason) {
        $state.FailureReason = if ($candidates.Count -eq 0) {
            'No winget.exe candidate found on this system.'
        } else {
            'All winget.exe candidates failed to produce a version.'
        }
    }

    return $state
}

function Repair-WinGetRegistration {
    <#
    .SYNOPSIS
        Re-registers an already-present DesktopAppInstaller package for the
        current user. This is the fix for Win32 1920.
    .DESCRIPTION
        When a package is provisioned (staged to WindowsApps) but not registered
        for the calling user, the alias stub exists and the payload does not
        resolve. Registration is per-user and therefore meaningless under
        SYSTEM - there the correct answer is to invoke the package binary
        directly, which Test-WinGetFunctional already does.
    #>
    [CmdletBinding()]
    param()

    if ($script:UsePortableMode) {
        Write-Verbose 'Portable server mode: App Installer package registration is intentionally skipped.'
        return $false
    }

    if (Test-IsSystemContext) {
        Write-Verbose 'SYSTEM context: per-user registration is not applicable; direct package-path invocation is used instead.'
        return $false
    }

    $pkg = Get-WinGetPackage
    if (-not $pkg) {
        Write-Verbose 'No DesktopAppInstaller package found to re-register.'
        return $false
    }

    if (Test-Path -LiteralPath $pkg.ManifestPath) {
        try {
            Write-Verbose "Registering manifest: $($pkg.ManifestPath)"
            Add-AppxPackage -DisableDevelopmentMode -Register $pkg.ManifestPath -ErrorAction Stop
            return $true
        } catch {
            Write-Verbose "Manifest registration failed: $($_.Exception.Message)"
        }
    }

    try {
        Write-Verbose "Registering by family name: $($script:WinGetFamilyName)"
        Add-AppxPackage -RegisterByFamilyName -MainPackage $script:WinGetFamilyName -ErrorAction Stop
        return $true
    } catch {
        Write-Verbose "RegisterByFamilyName failed: $($_.Exception.Message)"
        return $false
    }
}

function Test-VCRedistInstalled {
    <#
    .SYNOPSIS
        Checks if VC++ Redistributable 14.x is installed via registry and DLL presence.
    #>
    $is64Bit = [System.Environment]::Is64BitOperatingSystem
    $regPath = if ($is64Bit) {
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\X64"
    } else {
        "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X86"
    }

    $regExists = Test-Path -Path $regPath
    $dllExists = Test-Path -Path "$env:windir\System32\vcruntime140_1.dll"

    if ($regExists) {
        $major = (Get-ItemProperty -Path $regPath -Name 'Major' -ErrorAction SilentlyContinue).Major
        return ($major -eq 14 -and $dllExists)
    }
    return $false
}

function Get-OSInfo {
    <#
    .SYNOPSIS
        Returns OS version, type (Workstation/Server), and architecture.
    #>
    $reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $arch = switch -Regex ($os.OSArchitecture) {
        'ARM.*64' { 'arm64'; break }
        '64'      { 'x64'; break }
        '32|86'   { 'x86'; break }
        default   { $env:PROCESSOR_ARCHITECTURE.ToLowerInvariant() }
    }

    $isServer = $os.Caption -match "Server"
    $numericVersion = if ($isServer) {
        if ($os.Caption -match "(\d{4})") { [int]$Matches[1] } else { 0 }
    } else {
        [System.Environment]::OSVersion.Version.Major
    }

    $releaseId = $reg.ReleaseId
    if ([string]::IsNullOrEmpty($releaseId)) {
        $releaseId = $reg.DisplayVersion
    }

    [PSCustomObject]@{
        Name           = $os.Caption
        Type           = if ($isServer) { "Server" } else { "Workstation" }
        NumericVersion = $numericVersion
        ReleaseId      = $releaseId
        Architecture   = $arch
        BuildNumber    = $os.BuildNumber
        InstallationType = $reg.InstallationType
    }
}

function Install-NuGetIfRequired {
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            Write-Verbose "Installing NuGet PackageProvider..."
            try {
                Install-PackageProvider -Name "NuGet" -Force -ForceBootstrap -ErrorAction SilentlyContinue | Out-Null
            } catch {
                Write-Verbose "NuGet installation warning: $_"
            }
        }
    }
}

# ============================================================================ #
#  OS Compatibility Checks
# ============================================================================ #

Write-Step "Checking prerequisites"

if (-not (Test-AdminPrivileges)) {
    Write-Fail "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}
Write-Success "Running as Administrator"

if (Test-IsSystemContext) {
    Write-Host "  Context: LocalSystem (S-1-5-18) - App Execution Aliases will be bypassed." -ForegroundColor Gray
}

$osInfo = Get-OSInfo
Write-Host "  OS: $($osInfo.Name) ($($osInfo.Architecture))" -ForegroundColor Gray
Write-Host "  Build: $($osInfo.BuildNumber), Release: $($osInfo.ReleaseId)" -ForegroundColor Gray
Write-Host "  Installation type: $($osInfo.InstallationType)" -ForegroundColor Gray

if ($osInfo.Type -eq 'Workstation') {
    if ([int]$osInfo.BuildNumber -lt 17763) {
        Write-Fail 'WinGet requires Windows 10 version 1809 (build 17763) or later.'
        exit 1
    }
    if ($ExperimentalPortableServer) {
        Write-Fail '-ExperimentalPortableServer is valid only on Windows Server 2019/2022.'
        exit 1
    }
    Write-Success 'OS is supported by WinGet.'
} else {
    if ($osInfo.InstallationType -match 'Core') {
        Write-Fail 'WinGet cannot run on Windows Server Core, including portable mode.'
        exit 1
    }

    if ($osInfo.NumericVersion -ge 2025) {
        if ($ExperimentalPortableServer) {
            Write-Fail 'Windows Server 2025 supports packaged WinGet; do not use -ExperimentalPortableServer.'
            exit 1
        }
        Write-Success 'Windows Server version is supported by WinGet.'
    } elseif ($osInfo.NumericVersion -in @(2019, 2022)) {
        if (-not $ExperimentalPortableServer) {
            Write-Fail "Windows Server $($osInfo.NumericVersion) is not a supported WinGet platform."
            Write-Host '  Its MSIX implementation does not support the App Execution Alias required by packaged WinGet.' -ForegroundColor Yellow
            Write-Host '  Use Windows Server 2025+ for supported WinGet, or explicitly opt into the unsupported extraction method:' -ForegroundColor Yellow
            Write-Host '  .\Install-WinGetUltimate.ps1 -Force -ExperimentalPortableServer -Verbose' -ForegroundColor Yellow
            exit 3
        }

        $script:UsePortableMode = $true
        Write-Warning "UNSUPPORTED MODE: portable WinGet extraction on Windows Server $($osInfo.NumericVersion)."
        Write-Warning 'The Microsoft Store source and packaged App Installer servicing are not available in this mode.'
    } else {
        Write-Fail 'This Windows Server version is not supported.'
        exit 1
    }
}

# ---------------------------------------------------------------------------- #
#  Functional detection + in-place repair before falling through to reinstall
# ---------------------------------------------------------------------------- #

$wingetState = Test-WinGetFunctional

if (-not $wingetState.Working -and $wingetState.BinaryPresent) {
    Write-Info "winget binaries are present but not runnable."
    Write-Host "  Reason: $($wingetState.FailureReason)" -ForegroundColor Gray
    foreach ($attempt in $wingetState.Attempts) {
        Write-Verbose "  [$($attempt.Kind)] $($attempt.Path) -> ran=$($attempt.Ran) exit=$($attempt.ExitCode) win32=$($attempt.NativeErrorCode)"
    }

    Write-Info "Attempting in-place re-registration before reinstalling..."
    if (Repair-WinGetRegistration) {
        Start-Sleep -Seconds 2
        $wingetState = Test-WinGetFunctional
        if ($wingetState.Working) {
            Write-Success "WinGet repaired by re-registration (version: $($wingetState.Version))"
        } else {
            Write-Info "Re-registration did not restore winget; continuing with full installation."
        }
    } else {
        Write-Info "Re-registration not applicable or failed; continuing with full installation."
    }
}

if ($wingetState.Working) {
    Write-Success "WinGet is installed and runnable (version: $($wingetState.Version))"
    Write-Host "  Resolved via [$($wingetState.Kind)]: $($wingetState.ExePath)" -ForegroundColor Gray

    if (-not $SkipSourceFix) {
        Write-Step 'Validating WinGet sources'

        if ($script:AcceptAgreements) {
            $sourceHealth = Repair-WinGetSources -ExePath $wingetState.ExePath `
                -ResetDefaults:$Force `
                -RepairSourcePackage:($Force -and -not $script:UsePortableMode) `
                -SkipMicrosoftStore:$script:UsePortableMode
        } else {
            $sourceHealth = Test-WinGetSourceHealth -ExePath $wingetState.ExePath `
                -SkipMicrosoftStore:$script:UsePortableMode
        }

        foreach ($check in $sourceHealth.Checks) {
            if ($check.Healthy) {
                Write-Success "Source '$($check.Source)' is working."
            } else {
                Write-Warning "Source '$($check.Source)' failed (exit code $($check.ExitCode))."
                if ($check.AgreementPrompt) {
                    Write-Warning 'The source agreement has not been accepted for this execution identity.'
                }
                if ($check.MissingSourceData) {
                    Write-Warning 'The source data package is missing or corrupt (0x8a15000f).'
                }
                if ($check.PolicyBlocked) {
                    Write-Warning 'The source appears to be disabled by policy; this script will not override policy.'
                }
                if ($check.Output) { Write-Verbose $check.Output }
            }
        }

        if ($sourceHealth.Healthy) {
            if ($script:UsePortableMode) {
                Write-Success 'Portable WinGet and the community source are healthy.'
            } else {
                Write-Success 'WinGet and both built-in sources are healthy.'
            }
            if ($sourceHealth.LogPath) {
                Write-Host "  Native logs: $($sourceHealth.LogPath)" -ForegroundColor Gray
            }
            exit 0
        }

        if (-not $Force) {
            Write-Fail 'WinGet is present, but one or more sources are not usable.'
            if (-not $AcceptSourceAgreements) {
                Write-Host '  Run this script with -AcceptSourceAgreements for 0x8a150042.' -ForegroundColor Yellow
                Write-Host '  Run it with -Force for agreement acceptance plus source repair.' -ForegroundColor Yellow
            }
            if ($sourceHealth.LogPath) {
                Write-Host "  Native logs: $($sourceHealth.LogPath)" -ForegroundColor Gray
            }
            exit 1
        }

        Write-Info 'Source-only repair did not succeed; continuing with WinGet package repair.'
    } elseif (-not $Force) {
        Write-Success 'Source validation was skipped as requested.'
        exit 0
    }
} else {
    Write-Info "WinGet not detected. Proceeding with installation."
}

# ============================================================================ #
#  Visual C++ Redistributable
# ============================================================================ #

Write-Step "Visual C++ Redistributable"

if (Test-VCRedistInstalled) {
    Write-Success "VC++ Redistributable 14.x is already installed"
} else {
    Write-Info "Installing VC++ Redistributable..."
    $tempFolder = New-TempFolder

    try {
        $arch = $osInfo.Architecture
        $vcUrl = "https://aka.ms/vs/17/release/vc_redist.$arch.exe"
        $vcPath = Join-Path $tempFolder "vc_redist.$arch.exe"

        Write-Verbose "Downloading from $vcUrl"
        Invoke-WebRequest -Uri $vcUrl -OutFile $vcPath -UseBasicParsing
        Start-Process -FilePath $vcPath -ArgumentList "/install", "/quiet", "/norestart" -Wait

        if ($arch -eq "x64") {
            $vcUrlX86 = "https://aka.ms/vs/17/release/vc_redist.x86.exe"
            $vcPathX86 = Join-Path $tempFolder "vc_redist.x86.exe"
            Invoke-WebRequest -Uri $vcUrlX86 -OutFile $vcPathX86 -UseBasicParsing
            Start-Process -FilePath $vcPathX86 -ArgumentList "/install", "/quiet", "/norestart" -Wait
        }

        Write-Success "VC++ Redistributable installed."
    } catch {
        Write-Warning "VC++ Redistributable installation failed: $($_.Exception.Message)"
        Write-Warning "Continuing - winget may still work without it on newer Windows versions."
    } finally {
        Remove-TempFolder -Path $tempFolder
    }
}

# ============================================================================ #
#  WinGet Installation
# ============================================================================ #

Write-Step "Installing WinGet"

$installSuccess = $false
$tempFolder = New-TempFolder

try {
    # ----------------------------------------------------------------------- #
    #  Experimental portable route for unsupported Server 2019/2022
    # ----------------------------------------------------------------------- #

    if ($script:UsePortableMode) {
        Write-Info 'Using explicit experimental portable-server mode...'
        $installSuccess = Install-WinGetPortableServer -Architecture $osInfo.Architecture
    }

    # ----------------------------------------------------------------------- #
    #  Method 1: Repair-WinGetPackageManager (preferred for Win10/11)
    # ----------------------------------------------------------------------- #

    if (-not $installSuccess -and -not $script:UsePortableMode -and
        ($osInfo.Type -eq 'Workstation' -or ($osInfo.Type -eq 'Server' -and $osInfo.NumericVersion -ge 2025))) {
        Write-Info "Method 1: Using Microsoft.WinGet.Client module + Repair-WinGetPackageManager..."

        try {
            Install-NuGetIfRequired

            Write-Verbose "Installing Microsoft.WinGet.Client module..."
            Install-Module -Name Microsoft.WinGet.Client -Force -AllowClobber -Repository PSGallery -ErrorAction Stop

            Write-Verbose "Running Repair-WinGetPackageManager -AllUsers..."
            Repair-WinGetPackageManager -AllUsers -ErrorAction Stop

            Start-Sleep -Seconds 3

            if ((Test-WinGetFunctional).Working) {
                Write-Success "WinGet installed via Repair-WinGetPackageManager"
                $installSuccess = $true
            }
        } catch {
            Write-Warning "Method 1 failed: $($_.Exception.Message)"
            Write-Info "Trying next method..."
        }
    }

    # ----------------------------------------------------------------------- #
    #  Method 2: Direct download from GitHub with license + dependencies
    # ----------------------------------------------------------------------- #

    if (-not $installSuccess -and -not $script:UsePortableMode) {
        Write-Info "Method 2: Direct download from GitHub releases..."

        try {
            $arch = $osInfo.Architecture
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            Write-Verbose "Querying GitHub for latest winget release..."
            $releaseInfo = Get-LatestStableWinGetRelease

            $bundleAsset = $releaseInfo.assets | Where-Object {
                $_.name -eq 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
            } | Select-Object -First 1
            $dependencyAsset = $releaseInfo.assets | Where-Object {
                $_.name -eq 'DesktopAppInstaller_Dependencies.zip'
            } | Select-Object -First 1
            $licenseAsset = $releaseInfo.assets | Where-Object {
                $_.name -like '*_License1.xml'
            } | Select-Object -First 1

            if (-not $bundleAsset -or -not $dependencyAsset -or -not $licenseAsset) {
                throw 'The latest stable release is missing the bundle, dependency archive, or license asset.'
            }

            $bundlePath = Join-Path $tempFolder $bundleAsset.name
            Write-Verbose "Downloading $($bundleAsset.name)..."
            Invoke-WebRequest -Uri $bundleAsset.browser_download_url -OutFile $bundlePath -UseBasicParsing -ErrorAction Stop

            $licensePath = Join-Path $tempFolder $licenseAsset.name
            Write-Verbose "Downloading license..."
            Invoke-WebRequest -Uri $licenseAsset.browser_download_url -OutFile $licensePath -UseBasicParsing -ErrorAction Stop

            $dependencyZipPath = Join-Path $tempFolder $dependencyAsset.name
            $dependencyRoot = Join-Path $tempFolder 'Dependencies'
            Write-Verbose "Downloading release-matched dependencies..."
            Invoke-WebRequest -Uri $dependencyAsset.browser_download_url -OutFile $dependencyZipPath -UseBasicParsing -ErrorAction Stop
            Expand-Archive -LiteralPath $dependencyZipPath -DestinationPath $dependencyRoot -Force

            $dependencyPaths = @(
                Get-ChildItem -LiteralPath (Join-Path $dependencyRoot $arch) -File -Filter '*.appx' -ErrorAction Stop |
                    Select-Object -ExpandProperty FullName
            )
            if ($dependencyPaths.Count -eq 0) {
                throw "No release-matched dependencies were found for architecture '$arch'."
            }

            $bundleSignature = Get-AuthenticodeSignature -FilePath $bundlePath
            if ($bundleSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
                throw "The DesktopAppInstaller bundle signature is not valid: $($bundleSignature.Status)."
            }

            foreach ($dependencyPath in $dependencyPaths) {
                $dependencySignature = Get-AuthenticodeSignature -FilePath $dependencyPath
                if ($dependencySignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
                    throw "Dependency signature validation failed for '$dependencyPath': $($dependencySignature.Status)."
                }
                Write-Verbose "Installing dependency: $([IO.Path]::GetFileName($dependencyPath))"
                Add-AppxPackage -Path $dependencyPath -ErrorAction SilentlyContinue
            }

            Write-Verbose "Installing WinGet package with license..."
            try {
                Add-AppxProvisionedPackage -Online -PackagePath $bundlePath -LicensePath $licensePath `
                    -DependencyPackagePath $dependencyPaths -ErrorAction Stop | Out-Null
            } catch {
                Write-Verbose "Provisioned install failed ($($_.Exception.Message)), trying Add-AppxPackage..."
                Add-AppxPackage -Path $bundlePath -DependencyPath $dependencyPaths `
                    -InstallAllResources -ErrorAction Stop
            }

            Start-Sleep -Seconds 3

            # Provisioning stages the package but does not register it for the
            # calling identity - this is precisely the state that produces
            # Win32 1920 on the next run. Register before probing.
            [void](Repair-WinGetRegistration)

            if ((Test-WinGetFunctional).Working) {
                Write-Success "WinGet installed via GitHub release download."
                $installSuccess = $true
            }
        } catch {
            Write-Warning "Method 2 failed: $($_.Exception.Message)"
            Write-Info "Trying next method..."
        }
    }

    # ----------------------------------------------------------------------- #
    #  Method 3: aka.ms/getwinget shortcut + RegisterByFamilyName
    # ----------------------------------------------------------------------- #

    if (-not $installSuccess -and -not $script:UsePortableMode) {
        Write-Info "Method 3: aka.ms/getwinget + RegisterByFamilyName..."

        try {
            $bundlePath = Join-Path $tempFolder "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
            Invoke-WebRequest -Uri "https://aka.ms/getwinget" -OutFile $bundlePath -UseBasicParsing

            Add-AppxPackage -Path $bundlePath -ErrorAction Stop
            Add-AppxPackage -RegisterByFamilyName -MainPackage $script:WinGetFamilyName -ErrorAction SilentlyContinue

            Start-Sleep -Seconds 3

            if ((Test-WinGetFunctional).Working) {
                Write-Success "WinGet installed via aka.ms/getwinget"
                $installSuccess = $true
            }
        } catch {
            if ($_.Exception.Message -match '0x80073D06') {
                Write-Info 'A newer DesktopAppInstaller package is already installed; downgrade was intentionally skipped.'
                [void](Repair-WinGetRegistration)
                if ((Test-WinGetFunctional).Working) {
                    Write-Success 'The newer installed WinGet package is runnable.'
                    $installSuccess = $true
                }
            } else {
                Write-Warning "Method 3 failed: $($_.Exception.Message)"
            }
        }
    }

    if (-not $installSuccess) {
        if ($script:UsePortableMode) {
            Write-Fail 'Experimental portable WinGet could not be installed or started.'
            Remove-TempFolder -Path $tempFolder
            exit 1
        }

        # Binaries may still be on disk with a broken registration; report which.
        if (Test-WinGetExists) {
            Write-Fail "WinGet binaries are present but could not be made runnable."
            $final = Test-WinGetFunctional
            Write-Host "  Last failure: $($final.FailureReason)" -ForegroundColor Gray
        } else {
            Write-Fail "All installation methods failed. See warnings above for details."
        }
        Remove-TempFolder -Path $tempFolder
        exit 1
    }

} finally {
    Remove-TempFolder -Path $tempFolder
}

# ============================================================================ #
#  WinGet Source MSIX Registration (fixes 0x8a15000f)
# ============================================================================ #

if (-not $SkipSourceFix -and -not $script:UsePortableMode) {
    Write-Step 'Repairing the WinGet source package'
    [void](Install-WinGetSourcePackage)
} elseif ($script:UsePortableMode) {
    Write-Info 'Portable server mode: WinGet Source MSIX registration is skipped.'
}

# ============================================================================ #
#  Configure process PATH without modifying WindowsApps ACLs
# ============================================================================ #

Write-Step 'Configuring the current process'

$wingetPkg = Get-WinGetInstallation

if ($wingetPkg) {
    Write-Verbose "WinGet folder: $($wingetPkg.InstallLocation)"
    if (-not ($env:PATH -split ';' | Where-Object { $_ -eq $wingetPkg.InstallLocation })) {
        $env:PATH = "$($wingetPkg.InstallLocation);$env:PATH"
    }
    Write-Success 'Current-process PATH configured.'
} else {
    Write-Warning 'Could not locate the WinGet package folder.'
}

# ============================================================================ #
#  Final Verification
# ============================================================================ #

Write-Step "Verification"

# Refresh PATH for current session, keeping the resolved installation first.
$machinePath = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine')
$userPath    = [System.Environment]::GetEnvironmentVariable('PATH', 'User')
$resolvedLocation = if ($wingetPkg) { $wingetPkg.InstallLocation } else { $null }
$env:PATH    = (@($resolvedLocation, $machinePath, $userPath) |
                Where-Object { $_ }) -join ';'

Start-Sleep -Seconds 2

$finalState = Test-WinGetFunctional

if ($finalState.Working) {
    Write-Success "WinGet is installed and runnable (version: $($finalState.Version))"
    Write-Host "  Resolved via [$($finalState.Kind)]: $($finalState.ExePath)" -ForegroundColor Gray

    if ($script:UsePortableMode) {
        Write-Info 'Opening and testing the winget community source...'
    } else {
        Write-Info 'Opening and testing the winget and msstore sources...'
    }
    if ($script:AcceptAgreements) {
        $sourceHealth = Repair-WinGetSources -ExePath $finalState.ExePath `
            -ResetDefaults:$Force `
            -RepairSourcePackage:($Force -and -not $script:UsePortableMode) `
            -SkipMicrosoftStore:$script:UsePortableMode
    } else {
        $sourceHealth = Test-WinGetSourceHealth -ExePath $finalState.ExePath `
            -SkipMicrosoftStore:$script:UsePortableMode
    }

    foreach ($check in $sourceHealth.Checks) {
        if ($check.Healthy) {
            Write-Success "Source '$($check.Source)' is working."
        } else {
            Write-Warning "Source '$($check.Source)' failed (exit code $($check.ExitCode))."
            if ($check.AgreementPrompt) {
                Write-Warning 'Run with -AcceptSourceAgreements or -Force to accept the source agreement non-interactively.'
            }
            if ($check.Output) { Write-Verbose $check.Output }
        }
    }

    if (-not $sourceHealth.Healthy) {
        if ($sourceHealth.LogPath) {
            Write-Host "  Native logs: $($sourceHealth.LogPath)" -ForegroundColor Gray
        }
        Write-Fail 'WinGet was installed, but source verification failed.'
        exit 1
    }

    if ($sourceHealth.LogPath) {
        Write-Host "  Native logs: $($sourceHealth.LogPath)" -ForegroundColor Gray
    }

    if ($finalState.Kind -eq 'Package' -and -not $finalState.IsSystemContext) {
        Write-Host "  Note: resolved via the package path rather than the App Execution Alias." -ForegroundColor Gray
        Write-Host "  Sign out and back in for 'winget' to work as a bare command in new shells." -ForegroundColor Gray
    }
} elseif ($finalState.BinaryPresent) {
    $reportedLocation = if ($wingetPkg) { $wingetPkg.InstallLocation } else { 'an unresolved location' }
    Write-Warning "WinGet is installed at '$reportedLocation' but is not runnable in this context."
    Write-Warning "Reason: $($finalState.FailureReason)"
    foreach ($attempt in $finalState.Attempts) {
        Write-Host ("  [{0}] {1} -> ran={2} exit={3} win32={4}" -f `
            $attempt.Kind, $attempt.Path, $attempt.Ran, $attempt.ExitCode, $attempt.NativeErrorCode) -ForegroundColor Gray
    }
    Write-Host "`nWorkaround - invoke winget by full path:" -ForegroundColor Yellow
    if ($wingetPkg) {
        Write-Host "  & '$($wingetPkg.ExePath)' --version" -ForegroundColor Yellow
    }
    exit 1
} else {
    Write-Fail "WinGet installation could not be verified."
    Write-Host "Try restarting your computer and running this script again with -Force." -ForegroundColor Yellow
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  Installation Complete" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green
