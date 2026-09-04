<#
.SYNOPSIS
    Ultimate WinGet installer - installs winget and resolves all common issues.

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
    - Functional (not merely presence-based) winget detection
    - Repair of the "provisioned but not registered" state that produces
      ApplicationFailedException / Win32 1920 (ERROR_CANT_ACCESS_FILE)
    - WinGet Source MSIX registration (fixes 0x8a15000f)
    - PATH environment variable configuration
    - WindowsApps folder permissions fix

.PARAMETER Force
    Forces reinstallation even if Winget is already detected.

.PARAMETER SkipSourceFix
    Skips the WinGet Source MSIX registration step.

.PARAMETER Verbose
    Enables detailed output for troubleshooting.

.EXAMPLE
    .\Install-WinGetUltimate.ps1
    # Standard installation

.EXAMPLE
    .\Install-WinGetUltimate.ps1 -Force
    # Force reinstallation

.EXAMPLE
    .\Install-WinGetUltimate.ps1 -Force -Verbose
    # Force reinstallation with detailed output

.NOTES
    Version : 1.1.0
    Author  : Karol Kula
    Requires: Administrator privileges, Windows 10 1809+ or Server 2019+

    v1.1.0 - Detection layer rewritten.
             winget.exe is never invoked as a bare native command. The App
             Execution Alias in %LOCALAPPDATA%\Microsoft\WindowsApps is a
             zero-byte reparse stub that exists even when the MSIX package is
             not registered for the calling identity; invoking it raises a
             NativeCommandFailed / ApplicationFailedException that 2>$null
             does not suppress and that $ErrorActionPreference='Stop' turns
             into a script-terminating error.
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [switch]$Force,
    [switch]$SkipSourceFix
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ConfirmPreference = 'None'

$script:WinGetFamilyName  = 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe'
$script:WinGetPackageName = 'Microsoft.DesktopAppInstaller'

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
        5      { 'ERROR_ACCESS_DENIED (5) - WindowsApps ACL, AppLocker or WDAC policy is blocking execution.' }
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
    $pkg = Get-WinGetPackage
    if ($pkg) { return $pkg.InstallLocation }
    return $null
}

function Test-WinGetExists {
    <#
    .SYNOPSIS
        Tests whether winget binaries exist on disk, regardless of runnability.
    #>
    $pkg = Get-WinGetPackage
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
          1. The WindowsApps package binary (authoritative, works under SYSTEM)
          2. The per-user App Execution Alias (skipped under SYSTEM)
          3. Whatever is on PATH
    .OUTPUTS
        PSCustomObject: Working, ExePath, Version, Kind, BinaryPresent,
                        FailureReason, NativeErrorCode, Attempts.
    #>
    [CmdletBinding()]
    param([switch]$AllowAlias)

    $isSystem   = Test-IsSystemContext
    $pkg        = Get-WinGetPackage
    $candidates = New-Object System.Collections.Generic.List[object]

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
        BinaryPresent   = ($null -ne $pkg)
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
    $arch = ($os.OSArchitecture -replace "[^\d]").Trim()
    if ($arch -eq "64") { $arch = "x64" } elseif ($arch -eq "32") { $arch = "x86" }

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

function Add-WinGetToPath {
    <#
    .SYNOPSIS
        Adds winget folder to system and process PATH if not already present.
    .DESCRIPTION
        Note: the WindowsApps package folder name contains the package version,
        so a persisted machine PATH entry becomes stale on every winget update.
        Stale entries are pruned here to stop them accumulating.
    #>
    param([string]$WinGetFolder)

    if ([string]::IsNullOrEmpty($WinGetFolder)) { return }

    if (-not ($env:PATH -split ';' | Where-Object { $_ -eq $WinGetFolder })) {
        $env:PATH += ";$WinGetFolder"
        Write-Verbose "Added '$WinGetFolder' to process PATH."
    }

    $systemPath = [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine)
    $entries = @($systemPath -split ';' | Where-Object { $_ })

    # Drop stale versioned DesktopAppInstaller entries other than the current one.
    $pruned = @($entries | Where-Object {
        ($_ -notlike "*$($script:WinGetPackageName)_*") -or ($_ -eq $WinGetFolder)
    })

    if (-not ($pruned | Where-Object { $_ -eq $WinGetFolder })) {
        $pruned += $WinGetFolder
    }

    if (($pruned -join ';') -ne ($entries -join ';')) {
        [System.Environment]::SetEnvironmentVariable('PATH', ($pruned -join ';'), [System.EnvironmentVariableTarget]::Machine)
        Write-Verbose "Updated system PATH (current winget folder: '$WinGetFolder')."
    }
}

function Set-WinGetFolderPermissions {
    <#
    .SYNOPSIS
        Grants Administrators full control over the winget folder (language-independent SID).
    .NOTES
        Modifying ACLs under C:\Program Files\WindowsApps changes MSIX package
        integrity for every packaged app on the box and is flagged by CIS and
        the Microsoft security baselines. Prefer invoking winget.exe by its
        resolved package path over relaxing these ACLs.
    #>
    param([string]$FolderPath)

    if ([string]::IsNullOrEmpty($FolderPath) -or -not (Test-Path $FolderPath)) { return }

    try {
        $adminSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $adminGroup = $adminSid.Translate([System.Security.Principal.NTAccount])
        $acl = Get-Acl -Path $FolderPath
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $adminGroup, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $FolderPath -AclObject $acl
        Write-Verbose "Set Administrators full control on '$FolderPath'."
    } catch {
        Write-Verbose "ACL method failed, falling back to TAKEOWN/ICACLS..."
        & TAKEOWN /F $FolderPath /R /A /D Y 2>&1 | Out-Null
        & ICACLS $FolderPath /grant "*S-1-5-32-544:(F)" /T 2>&1 | Out-Null
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

if ($osInfo.Type -eq "Workstation" -and $osInfo.NumericVersion -lt 10) {
    Write-Fail "WinGet requires Windows 10 or later. Current OS is not supported."
    exit 1
}

if ($osInfo.Type -eq "Workstation" -and $osInfo.NumericVersion -eq 10 -and $osInfo.ReleaseId -lt 1809) {
    Write-Fail "WinGet requires Windows 10 version 1809 or later."
    exit 1
}

if ($osInfo.Type -eq "Server" -and $osInfo.NumericVersion -lt 2019) {
    Write-Fail "WinGet requires Windows Server 2019 or later."
    exit 1
}

Write-Success "OS is compatible"

# ---------------------------------------------------------------------------- #
#  Functional detection + in-place repair before falling through to reinstall
# ---------------------------------------------------------------------------- #

$wingetState = Test-WinGetFunctional

if ($wingetState.Working -and -not $Force) {
    Write-Success "WinGet is already installed and working (version: $($wingetState.Version))"
    Write-Host "  Resolved via [$($wingetState.Kind)]: $($wingetState.ExePath)" -ForegroundColor Gray
    Write-Host "`nUse -Force to reinstall." -ForegroundColor Yellow
    exit 0
}

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
            if (-not $Force) {
                Write-Host "  Resolved via [$($wingetState.Kind)]: $($wingetState.ExePath)" -ForegroundColor Gray
                Write-Host "`nUse -Force to reinstall anyway." -ForegroundColor Yellow
                exit 0
            }
        } else {
            Write-Info "Re-registration did not restore winget; continuing with full installation."
        }
    } else {
        Write-Info "Re-registration not applicable or failed; continuing with full installation."
    }
} elseif (-not $wingetState.Working) {
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
    #  Method 1: Repair-WinGetPackageManager (preferred for Win10/11)
    # ----------------------------------------------------------------------- #

    if ($osInfo.Type -eq "Workstation" -or ($osInfo.Type -eq "Server" -and $osInfo.NumericVersion -ge 2022)) {
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

    if (-not $installSuccess) {
        Write-Info "Method 2: Direct download from GitHub releases..."

        try {
            $arch = $osInfo.Architecture
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            $vclibsUrl = "https://aka.ms/Microsoft.VCLibs.$arch.14.00.Desktop.appx"
            $vclibsPath = Join-Path $tempFolder "Microsoft.VCLibs.appx"
            Write-Verbose "Downloading VCLibs..."
            Invoke-WebRequest -Uri $vclibsUrl -OutFile $vclibsPath -UseBasicParsing

            $uiXamlZipUrl = "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.8.6"
            $uiXamlZipPath = Join-Path $tempFolder "Microsoft.UI.Xaml.zip"
            Write-Verbose "Downloading UI.Xaml from NuGet..."
            Invoke-WebRequest -Uri $uiXamlZipUrl -OutFile $uiXamlZipPath -UseBasicParsing
            Expand-Archive -Path $uiXamlZipPath -DestinationPath (Join-Path $tempFolder "UIXaml") -Force
            $uiXamlAppxPath = Join-Path $tempFolder "UIXaml\tools\AppX\$arch\Release\Microsoft.UI.Xaml.2.8.appx"

            $releasesUri = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
            Write-Verbose "Querying GitHub for latest winget release..."
            $releaseInfo = Invoke-RestMethod -Uri $releasesUri -Method Get -ErrorAction Stop

            $bundleAsset = $releaseInfo.assets | Where-Object { $_.name -like "*Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" }
            $bundlePath = Join-Path $tempFolder $bundleAsset.name
            Write-Verbose "Downloading $($bundleAsset.name)..."
            Invoke-WebRequest -Uri $bundleAsset.browser_download_url -OutFile $bundlePath -UseBasicParsing

            $licenseAsset = $releaseInfo.assets | Where-Object { $_.name -like "*_License1.xml" }
            $licensePath = Join-Path $tempFolder $licenseAsset.name
            Write-Verbose "Downloading license..."
            Invoke-WebRequest -Uri $licenseAsset.browser_download_url -OutFile $licensePath -UseBasicParsing

            Write-Verbose "Installing VCLibs..."
            Add-AppxPackage -Path $vclibsPath -ErrorAction SilentlyContinue

            Write-Verbose "Installing UI.Xaml..."
            Add-AppxPackage -Path $uiXamlAppxPath -ErrorAction SilentlyContinue

            Write-Verbose "Installing WinGet package with license..."
            try {
                Add-AppxProvisionedPackage -Online -PackagePath $bundlePath -LicensePath $licensePath -DependencyPackagePath $uiXamlAppxPath, $vclibsPath -ErrorAction Stop | Out-Null
            } catch {
                Write-Verbose "Provisioned install failed ($($_.Exception.Message)), trying Add-AppxPackage..."
                Add-AppxPackage -Path $bundlePath -DependencyPath $uiXamlAppxPath, $vclibsPath -InstallAllResources -ErrorAction Stop
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

    if (-not $installSuccess) {
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
            Write-Warning "Method 3 failed: $($_.Exception.Message)"
        }
    }

    if (-not $installSuccess) {
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

if (-not $SkipSourceFix) {
    Write-Step "Registering WinGet Source packages."

    try {
        Write-Info "Installing source.msix from CDN..."
        try {
            Add-AppxPackage -Path "https://cdn.winget.microsoft.com/cache/source.msix" -ErrorAction Stop
            Write-Success "source.msix installed from CDN"
        } catch {
            Write-Verbose "CDN source.msix install failed: $($_.Exception.Message)"
        }

        Write-Info "Re-registering existing WinGet Source manifests..."
        $manifests = Get-ChildItem "C:\Program Files\WindowsApps\Microsoft.Winget.Source_*\AppXManifest.xml" -ErrorAction SilentlyContinue
        foreach ($manifest in $manifests) {
            try {
                Add-AppxPackage -DisableDevelopmentMode -Register $manifest.FullName -ErrorAction SilentlyContinue
                Write-Verbose "Registered: $($manifest.FullName)"
            } catch {
                Write-Verbose "Failed to register $($manifest.FullName): $($_.Exception.Message)"
            }
        }

        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.Winget.Source_8wekyb3d8bbwe -ErrorAction SilentlyContinue

        Write-Success "WinGet Source registration complete."
    } catch {
        Write-Warning "Source registration encountered issues: $($_.Exception.Message)"
        Write-Warning "You may need to run 'winget source reset --force' after installation."
    }
}

# ============================================================================ #
#  Fix Permissions & Environment PATH
# ============================================================================ #

Write-Step "Configuring permissions and PATH."

$wingetPkg = Get-WinGetPackage

if ($wingetPkg) {
    Write-Verbose "WinGet folder: $($wingetPkg.InstallLocation)"

    Set-WinGetFolderPermissions -FolderPath $wingetPkg.InstallLocation
    Write-Success "Permissions configured."

    Add-WinGetToPath -WinGetFolder $wingetPkg.InstallLocation
    Write-Success "PATH configured."
} else {
    Write-Warning "Could not locate WinGet folder in WindowsApps. PATH not updated."
}

# ============================================================================ #
#  Final Verification
# ============================================================================ #

Write-Step "Verification"

# Refresh PATH for current session, keeping the resolved package folder first.
$machinePath = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine')
$userPath    = [System.Environment]::GetEnvironmentVariable('PATH', 'User')
$env:PATH    = (@($wingetPkg.InstallLocation, $machinePath, $userPath) |
                Where-Object { $_ }) -join ';'

Start-Sleep -Seconds 2

$finalState = Test-WinGetFunctional

if ($finalState.Working) {
    Write-Success "WinGet is installed and runnable (version: $($finalState.Version))"
    Write-Host "  Resolved via [$($finalState.Kind)]: $($finalState.ExePath)" -ForegroundColor Gray

    Write-Info "Testing winget source..."
    $sourceRun = Invoke-WinGetProcess -ExePath $finalState.ExePath `
                                      -Arguments @('source', 'list', '--disable-interactivity') `
                                      -TimeoutSeconds 90

    if ($sourceRun.Ran -and $sourceRun.ExitCode -eq 0) {
        Write-Success "WinGet sources are working."
        Write-Host "Sources:`n$($sourceRun.StdOut)" -ForegroundColor Gray
    } else {
        $detail = if ($sourceRun.ErrorMessage) { $sourceRun.ErrorMessage } else { "exit code $($sourceRun.ExitCode)" }
        Write-Warning "WinGet sources may need attention ($detail). Try: winget source reset --force"
    }

    if ($finalState.Kind -ne 'Alias' -and -not $finalState.IsSystemContext) {
        Write-Host "  Note: resolved via the package path rather than the App Execution Alias." -ForegroundColor Gray
        Write-Host "  Sign out and back in for 'winget' to work as a bare command in new shells." -ForegroundColor Gray
    }
} elseif ($finalState.BinaryPresent) {
    Write-Warning "WinGet is installed at '$($wingetPkg.InstallLocation)' but is not runnable in this context."
    Write-Warning "Reason: $($finalState.FailureReason)"
    foreach ($attempt in $finalState.Attempts) {
        Write-Host ("  [{0}] {1} -> ran={2} exit={3} win32={4}" -f `
            $attempt.Kind, $attempt.Path, $attempt.Ran, $attempt.ExitCode, $attempt.NativeErrorCode) -ForegroundColor Gray
    }
    Write-Host "`nWorkaround - invoke winget by full path:" -ForegroundColor Yellow
    Write-Host "  & '$($wingetPkg.ExePath)' --version" -ForegroundColor Yellow
    exit 1
} else {
    Write-Fail "WinGet installation could not be verified."
    Write-Host "Try restarting your computer and running this script again with -Force." -ForegroundColor Yellow
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  Installation Complete" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green