# https://www.stigviewer.com/stig/microsoft_windows_server_20122012_r2_member_server/2023-02-27/finding/V-225493
# https://www.blumira.com/integration/how-to-disable-null-session-in-windows/
$RegPathLSA = "registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa"

function Test-RegistryValue 
{
  param
  (
    [Parameter(Mandatory=$true,Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$key,
    [Parameter(Mandatory=$true,Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]$value
  )
    $data = Get-ItemProperty -Path $key -Name $value -ErrorAction SilentlyContinue
 
    if ($data) {
        $true
    }
    else {
        $false
    }
}

if(-not $(Test-RegistryValue -key  $RegPathLSA -value RestrictAnonymous)){
    New-ItemProperty -Path $RegPathLSA -Name RestrictAnonymous -PropertyType Dword -Value 1    
}
Else{
    Set-ItemProperty -Path $RegPathLSA -Name RestrictAnonymous -Value 1    
}

if(-not $(Test-RegistryValue -key  $RegPathLSA -value RestrictAnonymousSAM)){
    New-ItemProperty -Path $RegPathLSA -Name RestrictAnonymousSAM -PropertyType Dword -Value 1    
}
Else{
    Set-ItemProperty -Path $RegPathLSA -Name RestrictAnonymousSAM -Value 1    
}
if(-not $(Test-RegistryValue -key  $RegPathLSA -value EveryoneIncludesAnonymous)){
    New-ItemProperty -Path $RegPathLSA -Name EveryoneIncludesAnonymous -PropertyType Dword -Value 0    
}
Else{
    Set-ItemProperty -Path $RegPathLSA -Name EveryoneIncludesAnonymous -Value 0    
}
