# Check SSL/TLS configuration on Server:
# https://www.ssllabs.com/ssltest/
# https://medium.com/@erdevendra/disable-legacy-tls-protocols-in-windows-systems-6e092eadd33d

#region Functions:
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

Function Set-SSLTLSConfiguration {
    param (
        [parameter(Mandatory=$true)] [ValidateSet("SSL2","SSL3","TLS10","TLS11","TLS12","TLS13")]$Protocol,
        [parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [ValidateSet("Enabled","Disabled")]$Status
    )

    Write-Host "`n🔐 Configuring $Protocol as $Status..."

    $ValuePairs = if ($Status -eq 'Enabled') {
        @{ 'Enabled' = 1; 'DisabledByDefault' = 0 }
    } else {
        @{ 'Enabled' = 0; 'DisabledByDefault' = 1 }
    }

    $ProtocolRegKey = switch ($Protocol) {
        "SSL2"  { 'SSL 2.0' }
        "SSL3"  { 'SSL 3.0' }
        "TLS10" { 'TLS 1.0' }
        "TLS11" { 'TLS 1.1' }
        "TLS12" { 'TLS 1.2' }
        "TLS13" { 'TLS 1.3' }
    }

    $ProtocolsRegPath = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $RegPath = "registry::HKEY_LOCAL_MACHINE\$ProtocolsRegPath"

    if (-not (Test-Path "$RegPath\$ProtocolRegKey")) {
        Write-Host "➕ Creating protocol key: $ProtocolRegKey"
        $key = (Get-Item HKLM:\).OpenSubKey("$ProtocolsRegPath", $true)
        $key.CreateSubKey($ProtocolRegKey)
        $key.Close()
    }

    foreach ($Key in @('Client','Server')) {
        $fullKeyPath = "$RegPath\$ProtocolRegKey\$Key"

        if (-not (Test-Path $fullKeyPath)) {
            Write-Host "➕ Creating subkey: $fullKeyPath"
            New-Item -Path "$RegPath\$ProtocolRegKey" -Name $Key -Force | Out-Null
        }

        foreach ($Value in $ValuePairs.GetEnumerator()) {
            $currentValue = Get-ItemProperty -Path $fullKeyPath -Name $Value.Key -ErrorAction SilentlyContinue
            if ($null -eq $currentValue) {
                Write-Host "⚠️ Value '$($Value.Key)' not found in $fullKeyPath. Creating with value: $($Value.Value)"
                New-ItemProperty -Path $fullKeyPath -Name $Value.Key -Value $Value.Value -PropertyType 'DWord' -Force | Out-Null
            } elseif ($currentValue.$($Value.Key) -ne $Value.Value) {
                Write-Host "🔄 Updating '$($Value.Key)' in $fullKeyPath from $($currentValue.$($Value.Key)) to $($Value.Value)"
                Set-ItemProperty -Path $fullKeyPath -Name $Value.Key -Value $Value.Value -Force | Out-Null
            } else {
                Write-Verbose "✔ '$($Value.Key)' in $fullKeyPath is already set to $($Value.Value)"
                Write-Host "✔ '$($Value.Key)' in $fullKeyPath is correct ($($Value.Value))"
            }
        }
    }
}
#endregion Functions

# Weak CipherSuites
$WeakCipherSuites = @(
    "DES",
    "IDEA",
    "RC"
)

$CipherSuites = @()
Foreach($WeakCipherSuite in $WeakCipherSuites){
    $CipherSuites += Get-TlsCipherSuite -Name $WeakCipherSuite    
}

if($CipherSuites){
    Write-Output "Detected weak Cipher Suites: `n$($CipherSuites.Name)"

    Foreach($CipherSuite in $CipherSuites){
        Disable-TlsCipherSuite -Name $($CipherSuite.Name)
    }
}

$RegPath = "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"

# Ciphers to disable
$RegKeysDisable = @(
    'NULL',
    'DES 56/56',
    'Triple DES 168',
    'Triple DES 168/168',
    'RC2 40/128',
    'RC2 56/128',
    'RC2 56/56',
    'RC4 40/128',
    'RC4 56/128',
    'RC4 64/128',
    'RC4 128/128'
)

Foreach($RegKey in $RegKeysDisable){
    $keyPath = "$RegPath\$RegKey"
    if (-not (Test-Path $keyPath)) {
        Write-Host "➕ Creating cipher key: $RegKey"
        $key = (Get-Item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true)
        $key.CreateSubKey($RegKey)
        $key.Close()
        New-ItemProperty -Path $keyPath -Name 'Enabled' -PropertyType Dword -Value 0 -Force | Out-Null
    }

    $current = Get-ItemPropertyValue -Path $keyPath -Name 'Enabled'
    if ($current -ne 0) {
        Write-Host "🔄 Disabling cipher '$RegKey' (was $current)"
        Set-ItemProperty -Path $keyPath -Name 'Enabled' -Value 0 -Force | Out-Null
    } else {
        Write-Host "✔ Cipher '$RegKey' already disabled"
    }
}

# Ciphers to enable
$RegKeysEnable = @(
    'AES 128/128',
    'AES 256/256'
)

Foreach($RegKey in $RegKeysEnable){
    if(-not $(Test-Path -Path "$RegPath\$RegKey")){
        $key = (Get-Item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true)
        $key.CreateSubKey($RegKey)
        $key.Close()        
        New-ItemProperty -Path "$RegPath\$RegKey" -Name 'Enabled' -PropertyType Dword -Value 1 -Force | Out-Null
    }

    if($(Get-ItemPropertyValue -Path "$RegPath\$RegKey" -Name 'Enabled') -ne 1){
        Set-ItemProperty -Path "$RegPath\$RegKey" -Name 'Enabled' -Value 1 -Force | Out-Null
    }

}

# Disable MD5 Hashes
$HashesPath = 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes'
if(-not (Test-Path -Path "$HashesPath\MD5")){
    New-Item -Path $HashesPath -Name 'MD5' -Force
    New-ItemProperty -Path "$HashesPath\MD5" -Name 'Enabled' -PropertyType Dword -Value 0 -Force | Out-Null
}
Else{
    if(-not $(Test-RegistryValue -Path "$HashesPath\MD5" -Value 'Enabled')){
        New-ItemProperty -Path "$HashesPath\MD5" -Name 'Enabled' -PropertyType Dword -Value 0 -Force | Out-Null 
    }
    Else{
        if($(Get-ItemPropertyValue -Path "$HashesPath\MD5" -Name 'Enabled') -ne 0){
            Set-ItemProperty -Path "$HashesPath\MD5" -Name 'Enabled' -Value 0 -Force | Out-Null
        }
    }
}


# Set Protocols
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12,
    [Net.SecurityProtocolType]::Tls11 ;

Set-SSLTLSConfiguration -Protocol SSL2 -Status Disabled
Set-SSLTLSConfiguration -Protocol SSL3 -Status Disabled
Set-SSLTLSConfiguration -Protocol TLS10 -Status Disabled
Set-SSLTLSConfiguration -Protocol TLS11 -Status Enabled
Set-SSLTLSConfiguration -Protocol TLS12 -Status Enabled
if($((Get-WmiObject Win32_OperatingSystem).caption) -like "*2022*"){
    Set-SSLTLSConfiguration -Protocol TLS13 -Status Enabled
    [Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12,
    [Net.SecurityProtocolType]::Tls13 ;
}
