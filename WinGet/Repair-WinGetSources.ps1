<#
.SYNOPSIS
    Detects and repairs problems with the default WinGet community source.

.DESCRIPTION
    Performs progressively deeper source checks:

    1. Resolves and executes winget.exe.
    2. Verifies that the default "winget" source is registered.
    3. Refreshes the source unless -SkipSourceUpdate is used.
    4. Searches for known package IDs in the source index.
    5. Retrieves each package's detailed manifest with `winget show`.

    The final check detects failures that `winget source list` and
    `winget search` can miss, including stale or missing per-version manifest
    blobs that produce 0x80190194 / HTTP 404.

    When repair is required, the script downloads source.msix from Microsoft's
    WinGet CDN, validates its Authenticode signature and Microsoft signer,
    registers the package, refreshes the source, and repeats all health checks.
    If the minimally disruptive repair is insufficient, it performs a targeted
    reset of only the default "winget" source. Custom sources are preserved.

    WinGet source state is user-scoped. Run this script as the affected user in
    an elevated PowerShell session. The script intentionally refuses to run as
    LocalSystem because that would repair a different profile.

.PARAMETER DetectOnly
    Tests source health without making repairs. Exit code 20 means unhealthy.

.PARAMETER Force
    Repairs the source even when it currently passes validation and starts with
    a targeted reset of the default "winget" source.

.PARAMETER ProbePackageId
    Package IDs used to test both index search and detailed manifest retrieval.

.PARAMETER SkipSourceUpdate
    Does not refresh the source during the initial health test. Repairs always
    refresh the source before post-validation.

.PARAMETER AllowSystemContext
    Allows validation and repair of the LocalSystem profile's separate WinGet
    state. This does not repair any interactive user's WinGet source.

.PARAMETER LogPath
    Path used for the audit log.

.EXAMPLE
    .\Repair-WinGetSources.ps1
    # Detects source problems and repairs them only when necessary.

.EXAMPLE
    .\Repair-WinGetSources.ps1 -DetectOnly
    # Detection-only mode suitable for compliance checks.

.EXAMPLE
    .\Repair-WinGetSources.ps1 -Force -Verbose
    # Forces a targeted rebuild of the default source.

.EXAMPLE
    .\Repair-WinGetSources.ps1 -ProbePackageId 'Notepad++.Notepad++'
    # Tests and, when required, repairs the source used for a specific package.

.OUTPUTS
    PSCustomObject containing Status, Healthy, Repaired, Stage, ExitCode,
    FailureCategory, Message, and LogPath.

.NOTES
    Version : 1.0.0
    Author  : Karol Kula

    Exit codes:
      0  Source is healthy, or repair and post-validation succeeded.
      10 WinGet is not installed or winget.exe cannot be executed.
      11 LocalSystem context was detected; the affected user's state was not tested.
      20 Source is unhealthy in -DetectOnly or -WhatIf mode.
      21 A network, DNS, TLS, or proxy failure was detected; no automatic repair.
      30 Source repair failed with an exception.
      31 The downloaded source package failed signature or signer validation.
      32 Repair completed, but post-validation still failed.
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [switch]$DetectOnly,
    [switch]$Force,

    [ValidateNotNullOrEmpty()]
    [string[]]$ProbePackageId = @(
        'Microsoft.PowerShell',
        '7zip.7zip',
        'Notepad++.Notepad++'
    ),

    [switch]$SkipSourceUpdate,

    [switch]$AllowSystemContext,

    [ValidateNotNullOrEmpty()]
    [string]$LogPath = (
        Join-Path -Path $env:ProgramData -ChildPath (
            'WinGet\Logs\Repair-WinGetSources-{0}.log' -f (Get-Date -Format 'yyyyMMdd')
        )
    )
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ConfirmPreference = 'None'
$script:SourcePackageUri = 'https://cdn.winget.microsoft.com/cache/source.msix'

function Initialize-RepairLog {
    $parent = Split-Path -Path $LogPath -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
}

function Write-RepairLog {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message

    switch ($Level) {
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Host "[ERROR] $Message" -ForegroundColor Red }
        'DEBUG' { Write-Verbose $Message }
        default { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
    }

    try {
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    } catch {
        Write-Verbose "Unable to append to '$LogPath': $($_.Exception.Message)"
    }
}

function Write-ResultAndExit {
    param(
        [Parameter(Mandatory)]
        [string]$Status,

        [Parameter(Mandatory)]
        [bool]$Healthy,

        [Parameter(Mandatory)]
        [bool]$Repaired,

        [Parameter(Mandatory)]
        [int]$ProcessExitCode,

        [string]$Stage = '',
        [string]$FailureCategory = 'None',
        [string]$Message = ''
    )

    [PSCustomObject]@{
        Status          = $Status
        Healthy         = $Healthy
        Repaired        = $Repaired
        Stage           = $Stage
        ExitCode        = $ProcessExitCode
        FailureCategory = $FailureCategory
        Message         = $Message
        LogPath         = $LogPath
    } | Write-Output

    exit $ProcessExitCode
}

function Test-LocalSystemContext {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ($identity.User.Value -eq 'S-1-5-18')
}

function Get-WinGetCommandPath {
    $command = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $package = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue |
        Sort-Object -Property Version -Descending |
        Select-Object -First 1

    if ($package -and $package.InstallLocation) {
        $candidate = Join-Path -Path $package.InstallLocation -ChildPath 'winget.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    return $null
}

function Invoke-WinGetNative {
    param(
        [Parameter(Mandatory)]
        [string[]]$ArgumentList
    )

    $wingetPath = Get-WinGetCommandPath
    if (-not $wingetPath) {
        return [PSCustomObject]@{
            ExitCode = -1
            Output   = 'winget.exe could not be resolved.'
        }
    }

    Write-RepairLog -Level DEBUG -Message "Executing: winget.exe $($ArgumentList -join ' ')"

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $wingetPath @ArgumentList 2>&1) |
            ForEach-Object { $_.ToString() }
        $exitCode = $LASTEXITCODE
    } catch {
        $output = @($_.Exception.Message)
        $exitCode = -1
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    $text = ($output -join [Environment]::NewLine).Trim()
    Write-RepairLog -Level DEBUG -Message "WinGet exit code: $exitCode"
    if ($text) {
        Write-RepairLog -Level DEBUG -Message $text
    }

    [PSCustomObject]@{
        ExitCode = $exitCode
        Output   = $text
    }
}

function Get-WinGetFailureCategory {
    param(
        [string]$Stage,
        [string]$Output
    )

    if ($Stage -eq 'WinGetCommand') {
        return 'WinGetMissing'
    }

    if ($Output -match '(?i)0x80072ee7|0x80072efd|0x80072f8f|0x80072f0d|name.*not.*resolved|timed?\s*out|proxy|TLS|SSL|certificate.*chain') {
        return 'Network'
    }

    if ($Output -match '(?i)0x80190194|404|BlobNotFound|0x8a15000f|data required by the source is missing') {
        return 'SourceMetadata'
    }

    if ($Stage -match '^Source') {
        return 'SourceRegistration'
    }

    if ($Stage -match '^Search:|^Manifest:') {
        return 'Catalog'
    }

    return 'Unknown'
}

function New-SourceHealthResult {
    param(
        [bool]$Healthy,
        [string]$Stage,
        [int]$ExitCode,
        [string]$Message,
        [string]$Output = ''
    )

    [PSCustomObject]@{
        Healthy         = $Healthy
        Stage           = $Stage
        ExitCode        = $ExitCode
        FailureCategory = if ($Healthy) {
            'None'
        } else {
            Get-WinGetFailureCategory -Stage $Stage -Output $Output
        }
        Message         = $Message
        Output          = $Output
    }
}

function Test-WinGetSourceHealth {
    param(
        [ValidateNotNullOrEmpty()]
        [string[]]$PackageId,

        [switch]$DoNotUpdate
    )

    if (-not (Get-WinGetCommandPath)) {
        New-SourceHealthResult `
            -Healthy $false `
            -Stage 'WinGetCommand' `
            -ExitCode -1 `
            -Message 'winget.exe could not be resolved.'
        return
    }

    $version = Invoke-WinGetNative -ArgumentList @('--version')
    if ($version.ExitCode -ne 0) {
        New-SourceHealthResult `
            -Healthy $false `
            -Stage 'WinGetCommand' `
            -ExitCode $version.ExitCode `
            -Message 'winget.exe could not be executed.' `
            -Output $version.Output
        return
    }
    Write-RepairLog -Message "Detected WinGet $($version.Output)."

    $sourceList = Invoke-WinGetNative -ArgumentList @(
        'source', 'list',
        '--name', 'winget',
        '--disable-interactivity'
    )
    if ($sourceList.ExitCode -ne 0) {
        New-SourceHealthResult `
            -Healthy $false `
            -Stage 'SourceList' `
            -ExitCode $sourceList.ExitCode `
            -Message 'The default winget source is not registered or cannot be opened.' `
            -Output $sourceList.Output
        return
    }

    if (-not $DoNotUpdate) {
        $sourceUpdate = Invoke-WinGetNative -ArgumentList @(
            'source', 'update',
            '--name', 'winget',
            '--disable-interactivity'
        )
        if ($sourceUpdate.ExitCode -ne 0) {
            New-SourceHealthResult `
                -Healthy $false `
                -Stage 'SourceUpdate' `
                -ExitCode $sourceUpdate.ExitCode `
                -Message 'The default winget source could not be refreshed.' `
                -Output $sourceUpdate.Output
            return
        }
    }

    foreach ($id in $PackageId) {
        $search = Invoke-WinGetNative -ArgumentList @(
            'search',
            '--id', $id,
            '--exact',
            '--source', 'winget',
            '--accept-source-agreements',
            '--disable-interactivity'
        )
        if ($search.ExitCode -ne 0 -or $search.Output -notmatch [regex]::Escape($id)) {
            New-SourceHealthResult `
                -Healthy $false `
                -Stage "Search:$id" `
                -ExitCode $search.ExitCode `
                -Message "The source index could not return package '$id'." `
                -Output $search.Output
            return
        }

        $show = Invoke-WinGetNative -ArgumentList @(
            'show',
            '--id', $id,
            '--exact',
            '--source', 'winget',
            '--accept-source-agreements',
            '--disable-interactivity'
        )
        if ($show.ExitCode -ne 0) {
            New-SourceHealthResult `
                -Healthy $false `
                -Stage "Manifest:$id" `
                -ExitCode $show.ExitCode `
                -Message "The detailed manifest for '$id' could not be retrieved." `
                -Output $show.Output
            return
        }
    }

    New-SourceHealthResult `
        -Healthy $true `
        -Stage 'Complete' `
        -ExitCode 0 `
        -Message 'The default winget source passed registration, update, search, and manifest tests.'
}

function New-SourcePackageFolder {
    $name = 'WinGet_SourceRepair_{0}' -f ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $path = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath $name
    New-Item -Path $path -ItemType Directory -Force | Out-Null
    return $path
}

function Install-WinGetSourcePackage {
    $tempFolder = New-SourcePackageFolder
    $sourcePackagePath = Join-Path -Path $tempFolder -ChildPath 'source.msix'

    try {
        Write-RepairLog -Message "Downloading $script:SourcePackageUri."
        Invoke-WebRequest `
            -Uri $script:SourcePackageUri `
            -OutFile $sourcePackagePath `
            -UseBasicParsing

        $signature = Get-AuthenticodeSignature -FilePath $sourcePackagePath
        Write-RepairLog -Message "source.msix signature status: $($signature.Status); signer: $($signature.SignerCertificate.Subject)"

        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            $exception = [System.IO.InvalidDataException]::new(
                "source.msix has an invalid Authenticode signature: $($signature.StatusMessage)"
            )
            $exception.Data['SourceRepairExitCode'] = 31
            throw $exception
        }

        if ($signature.SignerCertificate.Subject -notmatch '(?i)O=Microsoft Corporation') {
            $exception = [System.IO.InvalidDataException]::new(
                "source.msix is not signed by Microsoft Corporation. Signer: $($signature.SignerCertificate.Subject)"
            )
            $exception.Data['SourceRepairExitCode'] = 31
            throw $exception
        }

        try {
            Add-AppxPackage -Path $sourcePackagePath -ErrorAction Stop | Out-Null
        } catch {
            $installedSource = Get-AppxPackage -Name Microsoft.Winget.Source -ErrorAction SilentlyContinue |
                Sort-Object -Property Version -Descending |
                Select-Object -First 1

            if (-not $installedSource -or -not $installedSource.InstallLocation) {
                throw
            }

            Write-RepairLog -Level WARN -Message (
                "Add-AppxPackage returned '$($_.Exception.Message)'. " +
                'Re-registering the currently installed signed source package.'
            )

            $manifest = Join-Path -Path $installedSource.InstallLocation -ChildPath 'AppxManifest.xml'
            Add-AppxPackage `
                -DisableDevelopmentMode `
                -Register $manifest `
                -ErrorAction Stop |
                Out-Null
        }

        Write-RepairLog -Message 'Microsoft-signed source.msix is installed and registered.'
    } finally {
        if (Test-Path -LiteralPath $tempFolder) {
            Remove-Item -LiteralPath $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Reset-DefaultWinGetSource {
    Write-RepairLog -Message 'Removing and resetting only the default winget source.'

    $remove = Invoke-WinGetNative -ArgumentList @(
        'source', 'remove',
        '--name', 'winget',
        '--disable-interactivity'
    )
    if ($remove.ExitCode -ne 0) {
        Write-RepairLog -Level DEBUG -Message (
            "Source removal returned exit code $($remove.ExitCode): $($remove.Output)"
        )
    }

    $reset = Invoke-WinGetNative -ArgumentList @(
        'source', 'reset',
        '--name', 'winget',
        '--force',
        '--disable-interactivity'
    )
    if ($reset.ExitCode -ne 0) {
        throw "Targeted source reset failed with exit code $($reset.ExitCode): $($reset.Output)"
    }
}

function Update-DefaultWinGetSource {
    $update = Invoke-WinGetNative -ArgumentList @(
        'source', 'update',
        '--name', 'winget',
        '--disable-interactivity'
    )
    if ($update.ExitCode -ne 0) {
        throw "Source update failed with exit code $($update.ExitCode): $($update.Output)"
    }
}

function Invoke-WinGetSourceRepair {
    param([switch]$ForceReset)

    if ($ForceReset) {
        Reset-DefaultWinGetSource
    }

    Install-WinGetSourcePackage
    Update-DefaultWinGetSource
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

Initialize-RepairLog
Write-RepairLog -Message (
    "Starting WinGet source validation. User='$([Security.Principal.WindowsIdentity]::GetCurrent().Name)', " +
    "DetectOnly=$DetectOnly, Force=$Force, ProbePackageId='$($ProbePackageId -join ',')'."
)

if ((Test-LocalSystemContext) -and -not $AllowSystemContext) {
    $message = (
        'LocalSystem context detected. WinGet source state is user-scoped; run the script ' +
        'as the affected user in an elevated session.'
    )
    Write-RepairLog -Level ERROR -Message $message
    Write-ResultAndExit `
        -Status 'WrongContext' `
        -Healthy $false `
        -Repaired $false `
        -ProcessExitCode 11 `
        -Stage 'ExecutionContext' `
        -FailureCategory 'WrongContext' `
        -Message $message
}

if (Test-LocalSystemContext) {
    Write-RepairLog -Level WARN -Message (
        'LocalSystem context was explicitly allowed. Only the LocalSystem profile source ' +
        'will be validated or repaired; interactive user profiles are unaffected.'
    )
}

$initial = Test-WinGetSourceHealth `
    -PackageId $ProbePackageId `
    -DoNotUpdate:$SkipSourceUpdate

if ($initial.Healthy -and -not $Force) {
    Write-RepairLog -Message $initial.Message
    Write-ResultAndExit `
        -Status 'Healthy' `
        -Healthy $true `
        -Repaired $false `
        -ProcessExitCode 0 `
        -Stage $initial.Stage `
        -Message $initial.Message
}

if (-not $initial.Healthy) {
    Write-RepairLog -Level WARN -Message (
        "$($initial.Message) Stage=$($initial.Stage), ExitCode=$($initial.ExitCode), " +
        "Category=$($initial.FailureCategory)."
    )
    if ($initial.Output) {
        Write-RepairLog -Level DEBUG -Message $initial.Output
    }
} else {
    Write-RepairLog -Message 'Source repair was explicitly forced.'
}

if ($initial.FailureCategory -eq 'WinGetMissing') {
    Write-ResultAndExit `
        -Status 'WinGetMissing' `
        -Healthy $false `
        -Repaired $false `
        -ProcessExitCode 10 `
        -Stage $initial.Stage `
        -FailureCategory $initial.FailureCategory `
        -Message $initial.Message
}

if ($DetectOnly -or $WhatIfPreference) {
    $status = if ($WhatIfPreference) { 'RepairSkippedByWhatIf' } else { 'Unhealthy' }
    Write-ResultAndExit `
        -Status $status `
        -Healthy $initial.Healthy `
        -Repaired $false `
        -ProcessExitCode 20 `
        -Stage $initial.Stage `
        -FailureCategory $initial.FailureCategory `
        -Message $initial.Message
}

if ($initial.FailureCategory -eq 'Network' -and -not $Force) {
    $message = (
        'A network, DNS, TLS, or proxy failure was detected. Source package reset was ' +
        'not attempted because it would not correct connectivity.'
    )
    Write-RepairLog -Level ERROR -Message $message
    Write-ResultAndExit `
        -Status 'NetworkFailure' `
        -Healthy $false `
        -Repaired $false `
        -ProcessExitCode 21 `
        -Stage $initial.Stage `
        -FailureCategory $initial.FailureCategory `
        -Message $message
}

if (-not $PSCmdlet.ShouldProcess('default WinGet community source', 'Validate and repair source package')) {
    Write-ResultAndExit `
        -Status 'RepairDeclined' `
        -Healthy $initial.Healthy `
        -Repaired $false `
        -ProcessExitCode 20 `
        -Stage $initial.Stage `
        -FailureCategory $initial.FailureCategory `
        -Message 'Source repair was declined.'
}

try {
    Invoke-WinGetSourceRepair -ForceReset:$Force

    $postRepair = Test-WinGetSourceHealth -PackageId $ProbePackageId

    if (-not $postRepair.Healthy -and -not $Force) {
        Write-RepairLog -Level WARN -Message (
            'The minimally disruptive repair was insufficient. Escalating to a ' +
            'targeted reset of only the default winget source.'
        )

        Invoke-WinGetSourceRepair -ForceReset
        $postRepair = Test-WinGetSourceHealth -PackageId $ProbePackageId
    }

    if (-not $postRepair.Healthy) {
        Write-RepairLog -Level ERROR -Message (
            "Post-validation failed. Stage=$($postRepair.Stage), " +
            "ExitCode=$($postRepair.ExitCode), Category=$($postRepair.FailureCategory)."
        )
        if ($postRepair.Output) {
            Write-RepairLog -Level DEBUG -Message $postRepair.Output
        }

        Write-ResultAndExit `
            -Status 'PostValidationFailed' `
            -Healthy $false `
            -Repaired $true `
            -ProcessExitCode 32 `
            -Stage $postRepair.Stage `
            -FailureCategory $postRepair.FailureCategory `
            -Message $postRepair.Message
    }

    Write-RepairLog -Message 'WinGet source repair completed and passed post-validation.'
    Write-ResultAndExit `
        -Status 'Repaired' `
        -Healthy $true `
        -Repaired $true `
        -ProcessExitCode 0 `
        -Stage $postRepair.Stage `
        -Message 'WinGet source repair completed and passed post-validation.'
} catch {
    $repairExitCode = 30
    if ($_.Exception.Data.Contains('SourceRepairExitCode')) {
        $repairExitCode = [int]$_.Exception.Data['SourceRepairExitCode']
    }

    Write-RepairLog -Level ERROR -Message "WinGet source repair failed: $($_.Exception.Message)"
    Write-ResultAndExit `
        -Status 'RepairFailed' `
        -Healthy $false `
        -Repaired $false `
        -ProcessExitCode $repairExitCode `
        -Stage 'Repair' `
        -FailureCategory 'RepairFailure' `
        -Message $_.Exception.Message
}
