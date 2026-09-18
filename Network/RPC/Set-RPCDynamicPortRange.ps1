$PortRange = "5000-5100"
# Create the RPC Internet subkey if missing
$rpcPath = "HKLM:\SOFTWARE\Microsoft\Rpc\Internet"
if (-not (Test-Path $rpcPath)) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Rpc" -Name "Internet" -Force
}

# Define constrained port range (101 ports)
New-ItemProperty -Path $rpcPath -Name "Ports" -PropertyType MultiString -Value $PortRange -Force
New-ItemProperty -Path $rpcPath -Name "PortsInternetAvailable" -PropertyType String -Value "Y" -Force
New-ItemProperty -Path $rpcPath -Name "UseInternetPorts" -PropertyType String -Value "Y" -Force

# Restart the RPC Endpoint Mapper service dependency (or reboot node)
Restart-Service -Name RpcEptMapper -Force -Confirm:$false
