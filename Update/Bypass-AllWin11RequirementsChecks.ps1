$RegPathSetup = "registry::HKEY_LOCAL_MACHINE\System\Setup"
$RegPathMoSetup = "registry::HKEY_LOCAL_MACHINE\System\Setup\MoSetup"

$RegValueNames = @(
    "BypassTPMCheck",
    "BypassSecureBootCheck",
    "BypassRAMCheck",
    "BypassStorageCheck",
    "BypassCPUCheck"
)

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

if(-not $(Test-Path -Path "$RegPathSetup\LabConfig")){
    New-Item -Path $RegPathSetup -Name LabConfig -Force
}

Foreach($RegValue in $RegValueNames){
    if(-not $(Test-RegistryValue -key  $RegPathSetup -value $RegValue)){
        New-ItemProperty -Path $RegPathSetup -Name $RegValue -PropertyType Dword -Value 1    
    }
    Else{
        Set-ItemProperty -Path $RegPathSetup -Name $RegValue -Value 1    
    }
}

if(-not $(Test-RegistryValue -key  $RegPathMoSetup -value AllowUpgradesWithUnsupportedTPMOrCPU)){
    New-ItemProperty -Path $RegPathMoSetup -Name AllowUpgradesWithUnsupportedTPMOrCPU -PropertyType Dword -Value 1    
}
Else{
    Set-ItemProperty -Path $RegPathMoSetup -Name AllowUpgradesWithUnsupportedTPMOrCPU -Value 1    
}
