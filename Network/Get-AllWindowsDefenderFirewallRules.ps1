Import-Module ImportExcel
Add-Type -AssemblyName System.Collections.Concurrent

# Variables
$Date = Get-Date -Format "yyyy_MM_dd-HH_mm"
$OuputPathForExcelReport = "$env:USERPROFILE\Desktop\FirewallRules_RunspaceMode_$($env:COMPUTERNAME)_$Date.xlsx"

# Define the policy stores
$PolicyStores = @(
    "ActiveStore",
    "PersistentStore",
    "RSOP",
    "SystemDefaults",
    "StaticServiceStore",
    "ConfigurableServiceStore"
)

# ConcurrentBag to store results
$AllFirewallRulesRS = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()

# Measure the start time
$StartTime = Get-Date

# Create and manage runspaces
$Runspaces = @()
$Pool = $null
$Pool = [runspacefactory]::CreateRunspacePool($([Environment]::ProcessorCount -1), [Environment]::ProcessorCount)
$Pool.Open()

foreach ($Store in $PolicyStores) {
    $Runspace = [powershell]::Create().AddScript({
        param($Store, $AllFirewallRulesRS)
        
        try {
            # Retrieve firewall rules from the current policy store
            $Rules = Get-NetFirewallRule -PolicyStore $Store |
                     ForEach-Object {
                         $AppFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_
                         $ServiceFilter = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $_
                         
                         [PSCustomObject]@{
                             Name               = $_.Name
                             ID                 = $_.ID
                             DisplayName        = $_.DisplayName
                             Group              = $_.Group
                             Profile            = $_.Profile
                             Enabled            = $_.Enabled
                             Action             = $_.Action
                             Direction          = $_.Direction
                             EdgeTraversalPolicy= $_.EdgeTraversalPolicy
                             Description        = $_.Description
                             Priority           = $_.Priority
                             ElementName        = $_.ElementName
                             Owner              = $_.Owner
                             Mandatory          = $_.Mandatory
                             Status             = $_.Status
                             SystemName         = $_.SystemName
                             #PSComputerName     = $_.PSComputerName
                             PolicyAppId        = $_.PolicyAppId
                             #ExecutionStrategy  = $_.ExecutionStrategy
                             #Caption            = $_.Caption
                             CommonName         = $_.CommonName
                             PolicyStore        = $Store
                             Platforms          = $_.Platforms -join "`n"
                             EnforcementStatus  = $_.EnforcementStatus -join "`n"
                             ApplicationPath    = if ($AppFilter) { $AppFilter.Program } else { "None" }
                             ServiceName        = if ($ServiceFilter) { $ServiceFilter.Service } else { "None" }
                         }
                     }
            # Add rules to the shared collection
            foreach ($Rule in $Rules) {
                $AllFirewallRulesRS.Add($Rule)
            }
        } catch {
            Write-Warning "Could not retrieve rules from $Store : $_"
        }
    }).AddArgument($Store).AddArgument($AllFirewallRulesRS)
    $Runspace.RunspacePool = $Pool
    $Runspaces += [PSCustomObject]@{
        Pipe    = $Runspace
        Handle  = $Runspace.BeginInvoke()
    }
}

# Wait for all runspaces to finish
foreach ($Runspace in $Runspaces) {
    $Runspace.Pipe.EndInvoke($Runspace.Handle)
    $Runspace.Pipe.Dispose()
}

# Close the pool
$Pool.Close()
$Pool.Dispose()

# Measure the end time
$EndTime = Get-Date
$Duration = $EndTime - $StartTime
Write-Host "Runspace execution completed in $($Duration.ToString("hh' hours 'mm' minutes 'ss' seconds'"))"

# Export all collected firewall rules to an Excel file
$AllFirewallRulesRS  | Export-Excel -Path $OuputPathForExcelReport -AutoSize -TableName "FirewallRules"
$Duration.Gettype()
# Notify the user
Write-Host "Firewall rules exported to $OuputPathForExcelReport"
Write-Host "Report contains $($AllFirewallRulesRS.Count) Firewall Rules from all Stores $(($AllFirewallRulesRS | Select Name -Unique ).Count) of them are unique."
