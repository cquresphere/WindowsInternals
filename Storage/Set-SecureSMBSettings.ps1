# Disabling SMBv1 service Legacy
$SMB1ServiceRegPath = "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10\"

if(Test-Path -Path $SMB1ServiceRegPath){
    $SMB1ServiceRegValue = (Get-Item $SMB1ServiceRegPath | ForEach-Object {Get-ItemProperty $_.pspath}).Start
    if($SMB1ServiceRegValue -ne 4){
        Set-ItemProperty -Path $SMB1ServiceRegPath -Name Start -Value 4 -Force
    }
}

# Disabling SMBv1 and enabling SMBv2/SMBv3 for improved security
if(Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol) {
    Write-Host "SMBv1 protocol is enabled. Disabling it for better security..." -ForegroundColor Yellow
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
        Write-Host "SMBv1 protocol has been disabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to disable SMBv1 protocol: $_" -ForegroundColor Red
    }
} else {
    Write-Host "SMBv1 is already disabled." -ForegroundColor Green
}

# Removing SMBv1 registry keys if they exist
if(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol){
    Write-Host "SMBv1 Windows Feature is installed. Removing it..." -ForegroundColor Yellow
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop
        Write-Host "SMBv1 Windows Feature has been removed." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to remove SMBv1 Windows Feature: $_" -ForegroundColor Red
    }
} else {
    Write-Host "SMBv1 Windows Feature is already removed." -ForegroundColor Green
}

# Enabling SMBv2 and SMBv3 (these are enabled by default in modern Windows versions)
if(!(Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB2Protocol)) {
    Write-Host "SMBv2/SMBv3 is disabled. Enabling it..." -ForegroundColor Yellow
    try {
        Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -ErrorAction Stop
        Write-Host "SMBv2/SMBv3 has been enabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to enable SMBv2/SMBv3: $_" -ForegroundColor Red
    }
} else {
    Write-Host "SMBv2/SMBv3 is already enabled." -ForegroundColor Green
}

# Enable encryption for SMB server
if(!(Get-SmbServerConfiguration | Select-Object -ExpandProperty EncryptData)) {
    Write-Host "SMB encryption is disabled. Enabling it..." -ForegroundColor Yellow
    try {
        Set-SmbServerConfiguration -EncryptData $true -Force
        Write-Host "SMB encryption has been enabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to enable SMB encryption: $_" -ForegroundColor Red
    }
} else {
    Write-Host "SMB encryption is already enabled." -ForegroundColor Green
}

# EnableForcedLogoff for SMB sessions
if(!(Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableForcedLogoff)) {
    Write-Host "Forced Logoff for SMB sessions is disabled. Enabling it..." -ForegroundColor Yellow
    try {
        Set-SmbServerConfiguration -EnableForcedLogoff $true -Force
        Write-Host "Forced Logoff for SMB sessions has been enabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to enable Forced Logoff for SMB sessions: $_" -ForegroundColor Red
    }
} else {
    Write-Host "Forced Logoff for SMB sessions is already enabled." -ForegroundColor Green
}

# Enable SMB QUIC if supported (Windows Server 2022 and later)
if(!(Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMBQUIC)) {
    Write-Host "SMB over QUIC is disabled. Enabling it..." -ForegroundColor Yellow
    try{
        Set-SmbServerConfiguration -EnableSMBQUIC $true -Force
        Write-Host "SMB over QUIC has been enabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to enable SMB over QUIC: $_" -ForegroundColor Red    
    }
} else {
    Write-Host "SMB over QUIC is already enabled." -ForegroundColor Green
}

# Enable Strict Name Checking
if(!(Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableStrictNameChecking)) {
    Write-Host "Strict Name Checking is disabled. Enabling it..." -ForegroundColor Yellow
    try {
        Set-SmbServerConfiguration -EnableStrictNameChecking $true -Force
        Write-Host "Strict Name Checking has been enabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to enable Strict Name Checking: $_" -ForegroundColor Red
    }
} else {
    Write-Host "Strict Name Checking is already enabled." -ForegroundColor Green
}

# Configure SMB Authentication rate limiter
# https://learn.microsoft.com/en-us/windows-server/storage/file-server/configure-smb-authentication-rate-limiter?tabs=powershell#configure-smb-authentication-rate-limiter
if((Get-SmbServerConfiguration -ErrorAction SilentlyContinue).InvalidAuthenticationDelayTimeInMs){
    Write-Host "$($env:COMPUTERNAME) has SMB Authentication rate limiter available to configure." -ForegroundColor Cyan
    $CurrentDelay = (Get-SmbServerConfiguration).InvalidAuthenticationDelayTimeInMs
    $DesiredDelay = 2000
    if($CurrentDelay -ne $DesiredDelay){
        try{
            Set-SmbServerConfiguration -InvalidAuthenticationDelayTimeInMs $DesiredDelay -Force
            Write-Host "SMB Authentication rate limiter delay time has been set to $DesiredDelay ms." -ForegroundColor Green
        }
        catch{
            Write-Host "Failed to set SMB Authentication rate limiter delay time: $_" -ForegroundColor Red
        }
    }
    else{
        Write-Host "SMB Authentication rate limiter delay time is already set to $DesiredDelay ms." -ForegroundColor Green
    }
}
else{
    Write-Host "$($env:COMPUTERNAME) does not have SMB Authentication rate limiter available to configure." -ForegroundColor Yellow
}

# Enable RejectUnencryptedAccess    
if(!(Get-SmbServerConfiguration | Select-Object -ExpandProperty RejectUnencryptedAccess)) {
    Write-Host "Reject Unencrypted Access is disabled. Enabling it..." -ForegroundColor Yellow
    try {
        Set-SmbServerConfiguration -RejectUnencryptedAccess $true -Force
        Write-Host "Reject Unencrypted Access has been enabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to enable Reject Unencrypted Access: $_" -ForegroundColor Red
    }
} else {
    Write-Host "Reject Unencrypted Access is already enabled." -ForegroundColor Green
}

# Enable RequireSecuritySignature for SMB Client and Server
if((Get-SmbServerConfiguration).RequireSecuritySignature -ne $true -or (Get-SmbClientConfiguration).RequireSecuritySignature -ne $true){
    Write-Host "Enabling RequireSecuritySignature for SMB Client and Server..." -ForegroundColor Yellow
    try{
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        Set-SmbClientConfiguration -RequireSecuritySignature $true
        Write-Host "RequireSecuritySignature has been enabled for SMB Client and Server." -ForegroundColor Green
    }
    catch{
        Write-Host "Failed to enable RequireSecuritySignature: $_" -ForegroundColor Red
    }
}
else{
    Write-Host "RequireSecuritySignature is already enabled for SMB Client and Server." -ForegroundColor Green
}

# Require SMB Enryption for Client
if(!(Get-SmbClientConfiguration | Select-Object -ExpandProperty RequireEncryption)) {
    Write-Host "SMB Client Require Encryption is disabled. Enabling it..." -ForegroundColor Yellow
    try {
        Set-SmbClientConfiguration -RequireEncryption $true
        Write-Host "SMB Client Require Encryption has been enabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to enable SMB Client Require Encryption: $_" -ForegroundColor Red
    }
} else {
    Write-Host "SMB Client Require Encryption is already enabled." -ForegroundColor Green
}
