# https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-63687
$RegPathWinLogon = "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

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

if(-not $(Test-RegistryValue -key  $RegPathWinLogon -value cachedlogonscount)){
    New-ItemProperty -Path $RegPathWinLogon -Name cachedlogonscount -PropertyType String -Value 0    
}
Else{
    Set-ItemProperty -Path $RegPathWinLogon -Name cachedlogonscount -Value 0
}
