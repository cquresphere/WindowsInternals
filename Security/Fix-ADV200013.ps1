# https://msrc.microsoft.com/update-guide/en-US/vulnerability/ADV200013
$RegKeyPath = "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
$value = 'MaximumUdpPacketSize'
$data = '1221'

function Test-RegistryValue {
    param (
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()]$Path,
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()]$Value 
    )    
    try {    
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null return $true 
    }    
    catch {    
        return $false    
    }    
}

if(-not $(Test-RegistryValue -Path $RegKeyPath -Value $value)){
    New-ItemProperty -Path $RegKeyPath -Value $data -Name $value -PropertyType dword -Force
}
Else{
    Set-ItemProperty -Path $RegKeyPath -Value $data -Name $value
}
Restart-Service DNS -Force -Confirm:$false
