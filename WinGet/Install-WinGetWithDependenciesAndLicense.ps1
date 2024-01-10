# This script installs lates WinGet (Windows Package Manager) with dependencies and license file.

$assetPattern = "*Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
$licensePattern = "*_License1.xml"
$releasesUri = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
$asset = (Invoke-RestMethod -Uri $releasesUri -Method Get -ErrorAction stop).assets | Where-Object name -like $assetPattern
$downloadAssetUri = $asset.browser_download_url

$license = (Invoke-RestMethod -Uri $releasesUri -Method Get -ErrorAction stop).assets | Where-Object name -like $licensePattern
$downloadLicenseUri = $license.browser_download_url

if(-not $(Test-Path -Path "$env:TEMP\WinGet")){
    New-Item -Path "$env:TEMP" -Name "WinGet" -ItemType Directory -Force
}

$installerPath = "$env:TEMP\WinGet\$($asset.name)"
(New-Object System.Net.WebClient).DownloadFile($downloadAssetUri,$installerPath)
Unblock-File -Path $installerPath

$licensePath = "$env:TEMP\WinGet\$($license.name)"
(New-Object System.Net.WebClient).DownloadFile($downloadLicenseUri,$licensePath)
Unblock-File -Path $licensePath

# Dependencies
## Microsoft.UI.Xaml
$UIXamlPath = "$env:TEMP\WinGet\Microsoft.UI.Xaml.zip"
$downloadUIXamlUri = "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.7.0"
(New-Object System.Net.WebClient).DownloadFile($downloadUIXamlUri,$UIXamlPath)
Unblock-File -Path $UIXamlPath
Expand-Archive -Path $UIXamlPath -DestinationPath "$env:TEMP\WinGet\Microsoft.UI.Xaml"
$UIXamlAppxPath = "$env:TEMP\WinGet\Microsoft.UI.Xaml\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.7.appx"

## Microsoft.VCLibs.x64.14.00.Desktop
$VCLibsPath = "$env:TEMP\WinGet\Microsoft.VCLibs.x64.14.00.Desktop.appx"
$downloadVClibsUri = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
(New-Object System.Net.WebClient).DownloadFile($downloadVClibsUri,$VCLibsPath)

$VCLibs = Invoke-RestMethod -Uri $downloadVClibsUri -OutFile $VCLibsPath
Unblock-File -Path $VCLibsPath

Try{
    Add-AppxProvisionedPackage -Online -PackagePath $installerPath -LicensePath $licensePath -Verbose -LogPath "$env:TEMP\WinGet\DesktopAppInstaller_Install.log" -DependencyPackagePath "$UIXamlAppxPath", "$VCLibsPath"
}
Catch{
    try{
        Add-AppxPackage -Path $installerPath -DependencyPath "$UIXamlAppxPath", "$VCLibsPath" -InstallAllResources
    }
    catch{
        Write-Output $_.Exception.Message
        Write-Output $Error[0]
    }
}

# cleanup
Get-ChildItem -Path "$env:TEMP\WinGet" -Recurse | Where-Object { -not ($_.psiscontainer) } | Remove-Item -Force
Get-ChildItem -Path "$env:TEMP\WinGet" -Recurse  | Remove-Item -Force
Get-Item -Path "$env:TEMP\WinGet" | Remove-Item -Force 
