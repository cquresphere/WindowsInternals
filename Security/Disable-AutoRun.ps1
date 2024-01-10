# https://www.stigviewer.com/stig/windows_10/2019-09-25/finding/V-63673

function Test-RegistryValue {
    param (
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()]$Path,
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()]$Value 
    )    
    try {    
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null 
        return $true 
    }    
    catch {    
        return $false    
    }    
}

if(-not $(Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Value NoDriveTypeAutoRun)){
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name NoDriveTypeAutoRun -PropertyType Dword -Value 255    
}


# https://www.stigviewer.com/stig/windows_7/2014-04-02/finding/V-22692
if(-not $(Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Value NoAutorun )){
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name NoAutorun  -PropertyType Dword -Value 1   
}

if(-not $(Test-RegistryValue -Path "registry::HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Value NoDriveTypeAutoRun )){
    New-Item -Path "registry::HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\" -Name "Policies"
    New-Item -Path "registry::HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\" -Name "Explorer"
    New-ItemProperty -Path "registry::HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun  -PropertyType Dword -Value 255  -Force
}
