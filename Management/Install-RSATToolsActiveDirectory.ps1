<#
.SYNOPSIS
    Checks and installs Active Directory RSAT tools if they're not already installed.
.DESCRIPTION
    This script verifies if the RSAT: Active Directory DS-LDS Tools feature is installed,
    and if not, installs it using DISM for Windows 10/11 or the Add-WindowsCapability cmdlet.
.NOTES
    File Name      : Install-RSATAD.ps1
    Prerequisite   : PowerShell 5.1 or later, Windows 10/11 or Windows Server 2016/2019/2022
    Run as Administrator: Yes
#>

#Requires -RunAsAdministrator

function Test-RSATADInstalled {
    <#
    .SYNOPSIS
        Checks if RSAT: Active Directory DS-LDS Tools are installed.
    #>
    $installed = $false
    
    # Check different methods depending on OS version
    if ($PSVersionTable.PSVersion.Major -ge 7 -or [Environment]::OSVersion.Version -ge [Version]"10.0.17763") {
        # Windows 10 1809+ or Windows Server 2019+ or PowerShell 7+
        $capability = Get-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools*" -Online -ErrorAction SilentlyContinue
        if ($capability -and $capability.State -eq "Installed") {
            $installed = $true
        }
    }
    else {
        # Older Windows versions (pre-1809)
        $feature = Get-WindowsFeature -Name "RSAT-AD-Tools" -ErrorAction SilentlyContinue
        if ($feature -and $feature.Installed) {
            $installed = $true
        }
        
        # Alternative check for Windows 10
        $dismOutput = dism /online /get-featureinfo /featurename:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
        if ($dismOutput -match "State : Enabled") {
            $installed = $true
        }
    }
    
    return $installed
}

function Install-RSATAD {
    <#
    .SYNOPSIS
        Installs the RSAT: Active Directory DS-LDS Tools.
    #>
    try {
        Write-Host "Installing RSAT: Active Directory DS-LDS Tools..." -ForegroundColor Cyan
        
        if ($PSVersionTable.PSVersion.Major -ge 7 -or [Environment]::OSVersion.Version -ge [Version]"10.0.17763") {
            # Windows 10 1809+ or Windows Server 2019+ or PowerShell 7+
            $result = Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop
            if ($result.RestartNeeded) {
                Write-Host "A restart is required to complete the installation." -ForegroundColor Yellow
            }
        }
        else {
            # Older Windows versions (pre-1809)
            if (Get-Command -Name Install-WindowsFeature -ErrorAction SilentlyContinue) {
                # Server OS
                Install-WindowsFeature -Name "RSAT-AD-Tools" -ErrorAction Stop
            }
            else {
                # Windows 10 pre-1809
                dism /online /enable-feature /featurename:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 /norestart
            }
        }
        
        Write-Host "RSAT: Active Directory DS-LDS Tools installed successfully." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Failed to install RSAT: Active Directory DS-LDS Tools." -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
        return $false
    }
}

# Main script execution
Write-Host "Checking if RSAT: Active Directory DS-LDS Tools are installed..." -ForegroundColor Cyan

$isInstalled = Test-RSATADInstalled

if ($isInstalled) {
    Write-Host "RSAT: Active Directory DS-LDS Tools are already installed." -ForegroundColor Green
}
else {
    Write-Host "RSAT: Active Directory DS-LDS Tools are not installed." -ForegroundColor Yellow
    
    $confirmation = Read-Host "Do you want to install them now? (Y/N)"
    if ($confirmation -eq 'Y' -or $confirmation -eq 'y') {
        $installResult = Install-RSATAD
        if (-not $installResult) {
            exit 1
        }
    }
    else {
        Write-Host "Installation canceled by user." -ForegroundColor Yellow
    }
}
