# Check if running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "⚠️ This script must be run as Administrator."
    exit 1
}

$ErrorActionPreference = "Stop"

# Stop Windows Biometric Service
Write-Host "Stopping Windows Biometric Service..." -ForegroundColor Cyan
try {
    Stop-Service -Name "WbioSrvc" -Force
    Write-Host "Windows Biometric Service stopped." -ForegroundColor Green
}
catch {
    sc.exe stop WbioSrvc
    Write-Host "Windows Biometric Service stopped using sc.exe." -ForegroundColor Green
}

# Delete biometric data
$bioPath = "C:\Windows\System32\WinBioDatabase"
if (Test-Path $bioPath) {
    Write-Host "Deleting biometric data..."
    Remove-Item "$bioPath\*" -Force -Recurse -ErrorAction SilentlyContinue
}

# Stop Ngc folder access
try {
    $ngcPath = "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"
    Write-Host "Taking ownership of Ngc folder..."
    takeown /f $ngcPath /r /d y
    icacls $ngcPath /grant administrators:F /t
    Write-Host "Ownership of Ngc folder taken." -ForegroundColor Green
}
catch {
    Write-Error "Failed to take ownership of Ngc folder: $_"
    Write-Host "Starting back Windows Biometric Service..."
    Start-Service -Name "WbioSrvc"
    exit 1
}

# Delete Ngc folder contents
if (Test-Path $ngcPath) {
    Write-Host "Deleting Ngc folder contents..."
    Remove-Item "$ngcPath\*" -Force -Recurse -ErrorAction SilentlyContinue
}

# Restore default permissions on Ngc folder
try {
    Write-Host "Restoring default ACLs on Ngc folder..."
    icacls $ngcPath /reset /T
    icacls $ngcPath /grant "NT AUTHORITY\SYSTEM:(OI)(CI)(F)"
    icacls $ngcPath /grant "NT SERVICE\NgcCtnrSvc:(OI)(CI)(F)"
    Write-Host "Default ACLs restored on Ngc folder." -ForegroundColor Green
}
catch {
    Write-Error "Failed to restore ACLs on Ngc folder: $_"
    Write-Host "Starting back Windows Biometric Service..."
    Start-Service -Name "WbioSrvc"
    exit 1
}

# Restart Windows Biometric Service
Write-Host "Starting back Windows Biometric Service..."
Start-Service -Name "WbioSrvc"

Write-Host "`n✅ Windows Hello biometric and PIN data reset complete. Please reboot and reconfigure Windows Hello."
