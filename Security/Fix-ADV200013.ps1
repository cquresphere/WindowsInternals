#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies mitigation for ADV200013 DNS cache poisoning vulnerability.

.DESCRIPTION
    Sets MaximumUdpPacketSize registry value to 1221 to mitigate DNS cache poisoning.
    Reference: https://msrc.microsoft.com/update-guide/en-US/vulnerability/ADV200013

.EXAMPLE
    .\Fix-ADV200013.ps1 -Verbose
#>

[CmdletBinding()]
param()

$RegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
$ValueName = 'MaximumUdpPacketSize'
$ValueData = 1221

Write-Verbose "Starting ADV200013 mitigation script."

# Check if OS is Windows Server
Write-Verbose "Checking operating system type..."
$osCaption = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
Write-Verbose "Detected OS: $osCaption"

if ($osCaption -notlike "*Server*") {
    Write-Warning "This is not Windows Server. Script will exit."
    return
}
Write-Verbose "Windows Server detected - continuing."

# Check if DNS Server service exists
Write-Verbose "Checking if DNS Server service is installed..."
$dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue

if (-not $dnsService) {
    Write-Warning "DNS Server service not found. This server does not have the DNS role installed."
    return
}
Write-Verbose "DNS Server service found - Status: $($dnsService.Status)"

# Check if registry path exists
Write-Verbose "Checking registry path: $RegKeyPath"
if (-not (Test-Path -Path $RegKeyPath)) {
    Write-Error "Registry path does not exist: $RegKeyPath"
    return
}
Write-Verbose "Registry path exists"

# Get current value if it exists
Write-Verbose "Checking for existing $ValueName value..."
$currentValue = Get-ItemProperty -Path $RegKeyPath -Name $ValueName -ErrorAction SilentlyContinue

$restartRequired = $false

if ($null -eq $currentValue) {
    Write-Verbose "Value does not exist - creating new registry value."
    try {
        New-ItemProperty -Path $RegKeyPath -Name $ValueName -Value $ValueData -PropertyType DWord -Force | Out-Null
        Write-Verbose "Successfully created $ValueName with value $ValueData"
        $restartRequired = $true
    }
    catch {
        Write-Error "Failed to create registry value: $_"
        return
    }
}
else {
    $existingData = $currentValue.$ValueName
    Write-Verbose "Existing value found: $existingData"

    if ($existingData -eq $ValueData) {
        Write-Verbose "Value is already set to $ValueData - no changes needed."
    }
    else {
        Write-Verbose "Updating value from $existingData to $ValueData"
        try {
            Set-ItemProperty -Path $RegKeyPath -Name $ValueName -Value $ValueData
            Write-Verbose "Successfully updated $ValueName to $ValueData"
            $restartRequired = $true
        }
        catch {
            Write-Error "Failed to update registry value: $_"
            return
        }
    }
}

# Restart DNS service if changes were made
if ($restartRequired) {
    Write-Verbose "Restarting DNS service to apply changes..."
    try {
        Restart-Service -Name DNS -Force -ErrorAction Stop
        Write-Verbose "DNS service restarted successfully."
    }
    catch {
        Write-Error "Failed to restart DNS service: $_"
        return
    }
}

# Verify the change
Write-Verbose "Verifying registry value..."
$verifyValue = (Get-ItemProperty -Path $RegKeyPath -Name $ValueName).$ValueName

if ($verifyValue -eq $ValueData) {
    Write-Output "ADV200013 mitigation applied successfully. $ValueName = $verifyValue"
}
else {
    Write-Error "Verification failed. Expected $ValueData but found $verifyValue"
}
