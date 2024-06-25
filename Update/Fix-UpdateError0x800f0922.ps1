<#.based on MSN learn article:
  https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/error-0x800f0922-installing-windows-updates  
.#>

#region Find the staged update packages
$DismOutput = Dism.exe /english /online /get-packages /format:table | findstr /i "Staged"

$regex = '(Package_for_[^\]+~[^\~]+~[^\~]+~[^\~]+~[^\s]+)'

$matches = [regex]::Match($DismOutput[0], $regex)

$StagedPackages = @()
$RemovedPackages = @()
$ErrorPackages = @()

foreach($i in $DismOutput){
    $packageName = $null

    $matches = [regex]::Match($i, $regex)

    if ($matches.Success) {
        $packageName = $matches.Value

        $StagedPackages += $packageName
    } else {
        Write-Output "No match found"
    }
}
#endregion Find the staged update packages


#region Delete the staged update packages
Foreach($StagedPackage in $StagedPackages){
    Try{
        Write-Host "Trying to remove Staged Package: $StagedPackage" -ForegroundColor Cyan
        Dism.exe /online /remove-package /PackageName:$StagedPackage
        $RemovedPackages += $StagedPackage
    }
    Catch{
        Write-Host "Unable to remove Staged Package: $StagedPackage !" -ForegroundColor Red
        $ErrorPackages += $StagedPackage
        Write-Output $Error[0]
    }
}
#endregion Delete the staged update packages

#region Identify the SecureBootEncodeUEFI GUID
$SecureBootUEFIRegKey = "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\PI\SecureBootEncodeUEFI"
$IDGUIDValue = (Get-ItemProperty -Path $SecureBootUEFIRegKey -Name ID).ID
#endregion Identify the SecureBootEncodeUEFI GUID

#region Delete the SecureBootEncodeUEFI registry values
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Maintenance\$IDGUIDValue" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\$IDGUIDValue" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$IDGUIDValue" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\PI\SecureBootEncodeUEFI" /f
#endregion Delete the SecureBootEncodeUEFI registry values

if($null -ne $RemovedPackages){
    Write-Host "-----------------------------------------------------------------------------------"
    Write-Host "Script successfully removed packages: $RemovedPackages" -ForegroundColor Green
    Write-Host "-----------------------------------------------------------------------------------"
}

if($null -ne $ErrorPackages){
    Write-Host "-----------------------------------------------------------------------------------"
    Write-Host "Script was unable to removed packages: $RemovedPackages" -ForegroundColor Red
    Write-Host "-----------------------------------------------------------------------------------"
}
