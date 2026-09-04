<#
.SYNOPSIS
    Ultimate WinGet installer - installs winget and resolves all common issues.

.DESCRIPTION
    Comprehensive script that handles:
    - Admin privilege verification
    - OS compatibility checks
    - Visual C++ Redistributable installation
    - WinGet dependencies (VCLibs, UI.Xaml)
    - WinGet installation via multiple fallback methods:
        1. Repair-WinGetPackageManager (Microsoft.WinGet.Client module)
        2. Direct download from GitHub releases with license provisioning
        3. aka.ms/getwinget shortcut download
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
    Version : 1.0.0
    Author  : Karol Kula
    Requires: Administrator privileges, Windows 10 1809+ or Server 2019+
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
        # Extract year from caption for server
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

function Test-WinGetCommand {
    <#
    .SYNOPSIS
        Tests if winget.exe is available as a command.
    #>
    try {
        $null = Get-Command winget.exe -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Test-WinGetExists {
    <#
    .SYNOPSIS
        Tests if winget.exe exists in WindowsApps, even if not on PATH.
    #>
    $paths = @(Get-ChildItem "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_*__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue)
    return ($paths.Count -gt 0)
}

function Get-WinGetExePath {
    <#
    .SYNOPSIS
        Returns the folder path of the latest winget.exe in WindowsApps.
    #>
    $resolved = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" -ErrorAction SilentlyContinue
    if (-not $resolved) {
        $resolved = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_*__8wekyb3d8bbwe" -ErrorAction SilentlyContinue
    }
    if ($resolved) {
        return ($resolved | Sort-Object Path | Select-Object -Last 1).Path
    }
    return $null
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
    #>
    param([string]$WinGetFolder)

    if ([string]::IsNullOrEmpty($WinGetFolder)) { return }

    # Add to current process
    if (-not ($env:PATH -split ';' | Where-Object { $_ -eq $WinGetFolder })) {
        $env:PATH += ";$WinGetFolder"
        Write-Verbose "Added '$WinGetFolder' to process PATH."
    }

    # Add to system PATH persistently
    $systemPath = [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine)
    if (-not ($systemPath -split ';' | Where-Object { $_ -eq $WinGetFolder })) {
        $systemPath = $systemPath.TrimEnd(';') + ";$WinGetFolder"
        [System.Environment]::SetEnvironmentVariable('PATH', $systemPath, [System.EnvironmentVariableTarget]::Machine)
        Write-Verbose "Added '$WinGetFolder' to system PATH."
    }
}

function Set-WinGetFolderPermissions {
    <#
    .SYNOPSIS
        Grants Administrators full control over the winget folder (language-independent SID).
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

# Check if already installed
if ((Test-WinGetCommand) -and -not $Force) {
    $wingetVer = & winget.exe --version 2>$null
    Write-Success "WinGet is already installed and working (version: $wingetVer)"
    Write-Host "`nUse -Force to reinstall." -ForegroundColor Yellow
    exit 0
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

        # Also install x86 on 64-bit systems for full compatibility
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

            if (Test-WinGetExists) {
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

            # Download VCLibs dependency
            $vclibsUrl = "https://aka.ms/Microsoft.VCLibs.$arch.14.00.Desktop.appx"
            $vclibsPath = Join-Path $tempFolder "Microsoft.VCLibs.appx"
            Write-Verbose "Downloading VCLibs..."
            Invoke-WebRequest -Uri $vclibsUrl -OutFile $vclibsPath -UseBasicParsing

            # Download UI.Xaml dependency
            $uiXamlZipUrl = "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.8.6"
            $uiXamlZipPath = Join-Path $tempFolder "Microsoft.UI.Xaml.zip"
            Write-Verbose "Downloading UI.Xaml from NuGet..."
            Invoke-WebRequest -Uri $uiXamlZipUrl -OutFile $uiXamlZipPath -UseBasicParsing
            Expand-Archive -Path $uiXamlZipPath -DestinationPath (Join-Path $tempFolder "UIXaml") -Force
            $uiXamlAppxPath = Join-Path $tempFolder "UIXaml\tools\AppX\$arch\Release\Microsoft.UI.Xaml.2.8.appx"

            # Get latest winget release info from GitHub
            $releasesUri = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
            Write-Verbose "Querying GitHub for latest winget release..."
            $releaseInfo = Invoke-RestMethod -Uri $releasesUri -Method Get -ErrorAction Stop

            # Download winget msixbundle
            $bundleAsset = $releaseInfo.assets | Where-Object { $_.name -like "*Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" }
            $bundlePath = Join-Path $tempFolder $bundleAsset.name
            Write-Verbose "Downloading $($bundleAsset.name)..."
            Invoke-WebRequest -Uri $bundleAsset.browser_download_url -OutFile $bundlePath -UseBasicParsing

            # Download license
            $licenseAsset = $releaseInfo.assets | Where-Object { $_.name -like "*_License1.xml" }
            $licensePath = Join-Path $tempFolder $licenseAsset.name
            Write-Verbose "Downloading license..."
            Invoke-WebRequest -Uri $licenseAsset.browser_download_url -OutFile $licensePath -UseBasicParsing

            # Install dependencies first
            Write-Verbose "Installing VCLibs..."
            Add-AppxPackage -Path $vclibsPath -ErrorAction SilentlyContinue

            Write-Verbose "Installing UI.Xaml..."
            Add-AppxPackage -Path $uiXamlAppxPath -ErrorAction SilentlyContinue

            # Install winget with license (provisioned for all users)
            Write-Verbose "Installing WinGet package with license..."
            try {
                Add-AppxProvisionedPackage -Online -PackagePath $bundlePath -LicensePath $licensePath -DependencyPackagePath $uiXamlAppxPath, $vclibsPath -ErrorAction Stop | Out-Null
            } catch {
                Write-Verbose "Provisioned install failed ($($_.Exception.Message)), trying Add-AppxPackage..."
                Add-AppxPackage -Path $bundlePath -DependencyPath $uiXamlAppxPath, $vclibsPath -InstallAllResources -ErrorAction Stop
            }

            Start-Sleep -Seconds 3

            if (Test-WinGetExists) {
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
            Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction SilentlyContinue

            Start-Sleep -Seconds 3

            if (Test-WinGetExists) {
                Write-Success "WinGet installed via aka.ms/getwinget"
                $installSuccess = $true
            }
        } catch {
            Write-Warning "Method 3 failed: $($_.Exception.Message)"
        }
    }

    if (-not $installSuccess) {
        Write-Fail "All installation methods failed. See warnings above for details."
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
        # Method A: Download and install source.msix from CDN
        Write-Info "Installing source.msix from CDN..."
        try {
            Add-AppxPackage -Path "https://cdn.winget.microsoft.com/cache/source.msix" -ErrorAction Stop
            Write-Success "source.msix installed from CDN"
        } catch {
            Write-Verbose "CDN source.msix install failed: $($_.Exception.Message)"
        }

        # Method B: Re-register existing Winget.Source manifests (fixes 0x8a15000f)
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

        # Method C: Register by family name
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

$wingetFolder = Get-WinGetExePath

if ($wingetFolder) {
    Write-Verbose "WinGet folder: $wingetFolder"

    # Fix permissions
    Set-WinGetFolderPermissions -FolderPath $wingetFolder
    Write-Success "Permissions configured."

    # Add to PATH
    Add-WinGetToPath -WinGetFolder $wingetFolder
    Write-Success "PATH configured."
} else {
    Write-Warning "Could not locate WinGet folder in WindowsApps. PATH not updated."
}

# ============================================================================ #
#  Final Verification
# ============================================================================ #

Write-Step "Verification"

# Refresh PATH for current session
$env:PATH = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine') + ";" + [System.Environment]::GetEnvironmentVariable('PATH', 'User')

Start-Sleep -Seconds 2

if (Test-WinGetCommand) {
    $wingetVer = & winget.exe --version 2>$null
    Write-Success "WinGet is installed and recognized as a command (version: $wingetVer)"

    # Quick source test
    Write-Info "Testing winget source..."
    try {
        $sourceOutput = & winget.exe source list 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "WinGet sources are working."
            Write-Host "Sources:`n$sourceOutput" -ForegroundColor Gray
        } else {
            Write-Warning "WinGet sources may need attention. Try: winget source reset --force"
        }
    } catch {
        Write-Warning "Could not verify sources. Try: winget source reset --force"
    }
} elseif (Test-WinGetExists) {
    $wingetFolder = Get-WinGetExePath
    Write-Warning "WinGet is installed at '$wingetFolder' but not yet recognized as a command."
    Write-Warning "Please restart your PowerShell session or computer, then try 'winget --version'."
    Write-Host "`nAs a workaround, you can run winget directly:" -ForegroundColor Yellow
    Write-Host "  & '$wingetFolder\winget.exe' --version" -ForegroundColor Yellow
} else {
    Write-Fail "WinGet installation could not be verified."
    Write-Host "Try restarting your computer and running this script again with -Force." -ForegroundColor Yellow
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  Installation Complete" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green
