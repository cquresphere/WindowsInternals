$PSModules = @(
    'BitLocker'
)

Foreach($PSModule in $PSModules){
    if(-not $(Get-Module -Name $PSModule)){
        try{
            Install-Module -Name $PSModule -Force -ErrorAction Stop
        }
        catch{
            $global:Error[0].Exception.GetType().FullName
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $CallAPI = Invoke-WebRequest 'https://www.powershellgallery.com/api/v2'
            if($($CallAPI.StatusCode) -ne 200){
                Write-Host 'Check your network connection. Confirm that your firewall does not block the powershell.exe and the ieexec.exe' -ForegroundColor Red
                throw
            }
            Set-ExecutionPolicy RemoteSigned -Force

            Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
            try{
                Install-Module $PSModule -Force -AllowClobber -ErrorAction Stop
            }
            catch{
                $global:Error[0].Exception.GetType().FullName
                # Install module
                Install-Module $PSModule -Force -AllowClobber -ErrorAction Stop -SkipPublisherCheck

            }
        }
    }
    Import-Module -Name $PSModule
}

$BLinfo = Get-Bitlockervolume

if($blinfo.ProtectionStatus -eq 'On' -and $blinfo.EncryptionPercentage -eq '100'){
    Write-Host "'$env:computername - Protection is enabled and '$($blinfo.MountPoint)' is fully encrypted" -ForegroundColor Green
}
Elseif($blinfo.ProtectionStatus -eq 'On' -and $blinfo.EncryptionPercentage -ne '100'){
    Write-Host "'$env:computername - Protection is enabled and '$($blinfo.MountPoint)' is not encrypted $($blinfo.EncryptionPercentage)" -ForegroundColor Red
}
Else{
    Write-Host "'$env:computername - Protection is disabled and '$($blinfo.MountPoint)' is not encrypted $($blinfo.EncryptionPercentage)" -ForegroundColor Red
}
