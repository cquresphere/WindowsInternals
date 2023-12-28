# https://support.microsoft.com/en-us/topic/kb4072698-windows-server-and-azure-stack-hci-guidance-to-protect-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-2f965763-00e2-8f98-b632-0d96f30c8c8e

$CPUManufacturer = (Get-WmiObject -Class Win32_Processor | Select-Object -Property Manufacturer).Manufacturer

if($CPUManufacturer -eq 'GenuineIntel'){
    # Intel CPU

    # Check if Hyper-Threading is enabled
    $vCores = Get-WmiObject Win32_Processor | Measure -Property  NumberOfCores -Sum
    $vCores = $vCores.Sum
    $vLogicalCPUs = Get-WmiObject Win32_Processor | Measure -Property  NumberOfLogicalProcessors -Sum
    $vLogicalCPUs = $vLogicalCPUs.sum
    $HyperThreading = @()
    if ($vLogicalCPUs -gt $vCores) { 
       $HT="Hyper Threading: Enabled”
    } 
    else {  
        $HT="Hyper Threading: Disabled”
    }

    if($HT -eq "Hyper Threading: Enabled”){
        # if Hyper-Threading is enabled
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 72 /f
    }
    Else{
        # if Hyper-Threading is disabled
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 8264 /f
    }

    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f

    $hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online
    if($hyperv){
        # If the Hyper-V feature is installed
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /v MinVmVersionForCpuBasedMitigations /t REG_SZ /d "1.0" /f
    }
}
Else{
    # AMD CPU
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 67108928 /f

    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f 

    $hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online
    if($hyperv){
        # If the Hyper-V feature is installed
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /v MinVmVersionForCpuBasedMitigations /t REG_SZ /d "1.0" /f    
    }
}
