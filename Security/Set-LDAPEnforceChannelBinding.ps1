# https://support.microsoft.com/en-us/topic/kb4034879-use-the-ldapenforcechannelbinding-registry-entry-to-make-ldap-authentication-over-ssl-tls-more-secure-e9ecfa27-5e57-8519-6ba3-d2c06b21812e

$RegPath = "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$RegKey = "LdapEnforceChannelBinding"
$LDAPEnfChaBinValue = 2

<#
    DWORD value: 0 indicates disabled. No channel binding validation is performed. This is the behavior of all servers that have not been updated.
    DWORD value: 1 indicates enabled, when supported. All clients that are running on a version of Windows that has been updated to support channel binding tokens (CBT) must provide channel binding information to the server. Clients that are running a version of Windows that has not been updated to support CBT do not have to do so. This is an intermediate option that allows for application compatibility.
    DWORD value: 2 indicates enabled, always. All clients must provide channel-binding information. The server rejects authentication requests from clients that do not do so
#>

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

if(-not $(Test-RegistryValue -key  $RegPath -value $RegKey)){
    New-ItemProperty -Path $RegPath -Name $RegKey -PropertyType Dword -Value $LDAPEnfChaBinValue    
}
