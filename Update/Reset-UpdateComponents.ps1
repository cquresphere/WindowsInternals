# https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/additional-resources-for-windows-update

# Force Time Sync
w32tm.exe /resync /force

# Checking and Stopping the Windows Update services
$ServicesToStop = @(
    "bits",
    "wuauserv",
    "appidsvc",
    "cryptsvc",
    "msiserver"
)

Foreach ($Service in $ServicesToStop) {
    try {
        Stop-Service -Name $Service -Force
    }
    catch {
        Start-Sleep -Seconds 4
        try {
            Stop-Service -Name $Service -Force
        }
        catch {
            Start-Sleep -Seconds 8
            try {
                Stop-Service -Name $Service -Force
            }
            catch {
                Write-Output "Cannot Stop $Service"
            }
        }
    }
}

# Flush DNS
Ipconfig.exe /flushdns

# Del "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat"
$AppDownloaderPath = "$Env:ProgramData\Application Data\Microsoft\Network\Downloader\"
if (Test-Path $AppDownloaderPath) {
    Get-ChildItem -Path $AppDownloaderPath -Filter qmgr*.dat -ErrorAction SilentlyContinue | Remove-Item  -ErrorAction SilentlyContinue -Force
}

$MSFTDownloaderPath = "$Env:ProgramData\Microsoft\Network\Downloader\"
if (Test-Path $MSFTDownloaderPath) {
    Get-ChildItem -Path $MSFTDownloaderPath -Filter qmgr*.dat -ErrorAction SilentlyContinue | Remove-Item  -ErrorAction SilentlyContinue -Force
}

#Clear Windows Logs
Remove-Item $env:systemroot\WindowsUpdate.log -ErrorAction SilentlyContinue

$SoftwareDistributionPaths = @(
    "$env:Windir\SoftwareDistribution\DataStore",
    "$env:Windir\SoftwareDistribution\Download",
    "$env:Windir\System32\catroot2"
)
   
Foreach ($SoftwareDistributionPath in $SoftwareDistributionPaths) {
    $Path = $SoftwareDistributionPath + ".old"
    if (Test-Path $Path) {
        cmd.exe /c "rmdir /s /q $Path"
    }
    
    $Path = $SoftwareDistributionPath + ".bak"
    if (Test-Path $Path) {
        cmd.exe /c "rmdir /s /q $Path"
    }
    
    $NewName = (Get-Item -Path $SoftwareDistributionPath).Name + ".bak"
    cmd.exe /c "attrib -r -s -h /s /d $SoftwareDistributionPath"
    Rename-Item -Path $SoftwareDistributionPath -NewName $NewName -Force 
}

if (Test-Path -Path "$env:WinDir\winsxs\pending.xml.bak") {
    cmd.exe /c 'del /s /q /f "%SYSTEMROOT%\winsxs\pending.xml.bak"'
    cmd.exe /c "takeown /f '%SYSTEMROOT%\winsxs\pending.xml'"
    cmd.exe /c "attrib -r -s -h /s /d '%SYSTEMROOT%\winsxs\pending.xml'" 
    cmd.exe /c 'ren "%SYSTEMROOT%\winsxs\pending.xml" pending.xml.bak'
}

# Reset Windows Update policies
$WindowsUpdateRegKeys = @(
    "registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
    "registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate",
    "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
    "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"    
)
foreach ($WindowsUpdateRegKey in $WindowsUpdateRegKeys) {
    if (Test-Path $WindowsUpdateRegKey) {
        Remove-Item -Path $WindowsUpdateRegKey -Force -Confirm $false
    }
}

if (Test-ComputerSecureChannel) {
    cmd.exe /c "gpupdate.exe /force"
}

# Reset Security descriptors to default
cmd.exe /C "sc.exe sdset bits D:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
cmd.exe /C "sc.exe sdset wuauserv D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"

# Reregister the BITS and the Windows Update DLL files
Set-Location "$env:Windir\System32"

regsvr32.exe /s atl.dll
regsvr32.exe /s urlmon.dll
regsvr32.exe /s mshtml.dll
regsvr32.exe /s shdocvw.dll
regsvr32.exe /s browseui.dll
regsvr32.exe /s jscript.dll
regsvr32.exe /s vbscript.dll
regsvr32.exe /s scrrun.dll
regsvr32.exe /s msxml.dll
regsvr32.exe /s msxml3.dll
regsvr32.exe /s msxml6.dll
regsvr32.exe /s actxprxy.dll
regsvr32.exe /s softpub.dll
regsvr32.exe /s wintrust.dll
regsvr32.exe /s dssenh.dll
regsvr32.exe /s rsaenh.dll
regsvr32.exe /s gpkcsp.dll
regsvr32.exe /s sccbase.dll
regsvr32.exe /s slbcsp.dll
regsvr32.exe /s cryptdlg.dll
regsvr32.exe /s oleaut32.dll
regsvr32.exe /s ole32.dll
regsvr32.exe /s shell32.dll
regsvr32.exe /s initpki.dll
regsvr32.exe /s wuapi.dll
regsvr32.exe /s wuaueng.dll
regsvr32.exe /s wuaueng1.dll
regsvr32.exe /s wucltui.dll
regsvr32.exe /s wups.dll
regsvr32.exe /s wups2.dll
regsvr32.exe /s wuweb.dll
regsvr32.exe /s qmgr.dll
regsvr32.exe /s qmgrprxy.dll
regsvr32.exe /s wucltux.dll
regsvr32.exe /s muweb.dll
regsvr32.exe /s wuwebv.dll

# Reset WinSock 
netsh.exe winsock reset
netsh.exe winsock reset proxy

# Set the startup type as automatic
cmd.exe /c "sc config wuauserv start= auto"
cmd.exe /c "sc config bits start= auto"
cmd.exe /c "sc config DcomLaunch start= auto"

# Start Services
Foreach ($Service in $ServicesToStop) {
    try {
        Start-Service -Name $Service -Force
    }
    catch {
        Start-Sleep -Seconds 4
        try {
            Start-Service -Name $Service -Force
        }
        catch {
            Start-Sleep -Seconds 8
            try {
                Start-Service -Name $Service -Force
            }
            catch {
                Write-Output "Cannot Stop $Service"
            }
        }
    }
}

# Clear the BITS queue
Get-BitsTransfer | Remove-BitsTransfer 
bitsadmin.exe /reset /allusers

# Forcing discovery
wuauclt.exe /resetauthorization /detectnow 
 
Write-Host "Process complete. Please reboot your computer." -ForegroundColor Yellow
