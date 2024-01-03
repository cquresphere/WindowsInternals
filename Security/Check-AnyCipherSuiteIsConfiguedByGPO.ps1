# https://learn.microsoft.com/en-us/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/exchange-tls-configuration?view=exchserver-2019
$cipherSuiteKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"  
if (((Get-ItemProperty $cipherSuiteKeyPath).Functions).Count -ge 1) {
	Write-Host "Cipher suites are configured by Group Policy" -Foregroundcolor Red
} 
else {
    Write-Host "No cipher suites are configured by Group Policy - you can continue with the next steps" -Foregroundcolor Green    
}
