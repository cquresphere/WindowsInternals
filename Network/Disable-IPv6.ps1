#Variables
$RegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\"
$RegKeyValueName = "DisabledComponents"

#Remove binding from all network adapters 
Get-NetAdapterBinding -ComponentID "ms_tcpip6" | where Enabled -eq $true | Disable-NetAdapterBinding -ComponentID "ms_tcpip6"

#Disable IPv6 on Network Adapter
if(-not $(Test-RegistryValue -key $RegKeyPath -value $RegKeyValueName)){
    Write-Host "Registry Value $RegKeyValueName is not present on $RegKeyPath" -ForegroundColor Yellow
    try{
        New-ItemProperty -Path $RegKeyPath -Name $RegKeyValueName -Type DWord -Value 255 -ErrorAction Stop
        Write-Host "Registry Value: $RegKeyValueName has been created" -ForegroundColor Green
    }
    catch{
        Write-Host "Unable to create registry value: $RegKeyValueName for the registry key: $RegKeyPath" -ForegroundColor Red
    }
}
Else{
    if($(Get-ItemPropertyValue -Path $RegKeyPath -Name $RegKeyValueName ) -ne 255){
        try{
            New-ItemProperty -Path $RegKeyPath -Name $RegKeyValueName -Type DWord -Value 255 -ErrorAction Stop
            Write-Host "Registry Value: $RegKeyValueName has been created" -ForegroundColor Green
        }
        catch{
            Write-Host "Unable to create registry value: $RegKeyValueName for the registry key: $RegKeyPath" -ForegroundColor Red
        }
    }
}
