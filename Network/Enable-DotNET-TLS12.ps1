#region variables
$RegPaths = @(
    "registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727"
    "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727"
    "registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
)

$RegKeyNames = @(
    "SystemDefaultTlsVersions",
    "SchUseStrongCrypto"
)
#endregion variables

#region functions
Function Test-RegistryValue {
    param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name
        ,
        [Switch]$PassThru
    ) 
    process {
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
            if ($Key.GetValue($Name, $null) -ne $null) {
                if ($PassThru) {
                    Get-ItemProperty $Path $Name
                } else {
                    $true
                }
            } else {
                $false
            }
        } else {
            $false
        }
    }
}
#endregion functions

Foreach($RegKeyName in $RegKeyNames){
    Foreach($RegPath in $RegPaths){
        if(-not $(Test-RegistryValue -Path $RegPath -Name $RegKeyName)){
            New-ItemProperty -Path $RegPath -Name $RegKeyName -PropertyType Dword -Value 1
        }
        Else{
            $value = (Get-ItemProperty -Path $RegPath -Name $RegKeyName).$RegKeyName
            if($value -ne 1){
                Set-ItemProperty -Path $RegPath -Name $RegKeyName -Value 1
            }
        }
    }
}
