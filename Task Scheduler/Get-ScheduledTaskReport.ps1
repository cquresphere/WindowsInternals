# Variables
$Date = Get-Date -Format "yyyy_MM_dd"
$OuputPathForExcelReport = "C:\Temp\TaskScheduled_Report_$($env:COMPUTERNAME)_$Date.xlsx"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($Host.Version.Major -eq 5) {
    # Progress bar can significantly impact cmdlet performance
    # https://github.com/PowerShell/PowerShell/issues/2138
    $Script:ProgressPreference = "SilentlyContinue"
}

#region Install Modules
$PSModules = @(
    'ImportExcel'
)

$PackageProviderNames = (Get-PackageProvider).Name
if($PackageProviderNames -notcontains 'NuGet'){
    try{
        Write-Host 'Installing NuGet Package Provider' -ForegroundColor Cyan
        Install-PackageProvider -Name NuGet -minimumVersion 2.8.5.201 -Force -ErrorAction Stop
    }
    catch{
        # https://patchmypc.com/blog/no-match-was-found-while-installing-the-nuget-packageprovider/
        Write-Host "Error: $($global:Error[0].Exception.GetType().FullName)" -ForegroundColor Yellow
        Write-Host  "Second attempt Installing NuGet Package Provider with skipping certificate check" -ForegroundColor Cyan
Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        Install-PackageProvider -Name NuGet -Force
    }
}

Foreach($PSModule in $PSModules){
    if(-not $(Get-Module -Name $PSModule )){
        try{
            Write-Host "Installing Module: $PSModule" -ForegroundColor Cyan
            Install-Module -Name $PSModule -Force -ErrorAction Stop
        }
        catch{
            $global:Error[0].Exception.GetType().FullName
            Write-Host "Error: $($global:Error[0].Exception.GetType().FullName)" -ForegroundColor Yellow
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $CallAPI = Invoke-WebRequest 'https://www.powershellgallery.com/api/v2'
            if($($CallAPI.StatusCode) -ne 200){
                Write-Host 'Check your network connection. Confirm that your firewall does not block the powershell.exe and the ieexec.exe' -ForegroundColor Red
                throw
            }
            Set-ExecutionPolicy Bypass -Scope Process -Force

            Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
            try{
                Install-Module $PSModule -Force -AllowClobber -ErrorAction Stop
            }
            catch{
                $global:Error[0].Exception.GetType().FullName
                # Install module
                Install-Module $PSModule -Force -AllowClobber -ErrorAction Stop -SkipPublisherCheck

            }
        }
    }
    Else{
        Update-Module -Name $PSModule -Force
    }
    Import-Module -Name $PSModule
}
#endregion Install Modules

# Function to get Scheduled Task details including history and "who runs" the task
function Get-ScheduledTaskDetails {
    $tasks = Get-ScheduledTask | ForEach-Object {
        $task = $_
        $taskName = $task.TaskName
        $taskPath = $task.TaskPath

        # Extract Principal (Who runs the task)
        $principal = $task.Principal.UserId

        # Extract Triggers
        $triggers = $task.Triggers | ForEach-Object {
            $_ | Select-Object -Property @{
                Name = "TriggerType"; Expression = { $_.TriggerType }
            }, @{
                Name = "StartBoundary"; Expression = { $_.StartBoundary }
            }, @{
                Name = "EndBoundary"; Expression = { $_.EndBoundary }
            }, @{
                Name = "Enabled"; Expression = { $_.Enabled }
            }
        }

        # Extract Actions
        $actions = $task.Actions | ForEach-Object {
            $_ | Select-Object -Property @{
                Name = "ActionType"; Expression = { $_.ActionType }
            }, @{
                Name = "Command"; Expression = { $_.Execute }
            }, @{
                Name = "Arguments"; Expression = { $_.Arguments }
            }
        }

        # Extract Conditions
        $conditions = $task.Settings | Select-Object -Property StartWhenAvailable, AllowHardTerminate, DisallowStartIfOnBatteries, StopIfGoingOnBatteries

        # Get task history from Event Log
        $history = @()
        try {
            $history = Get-WinEvent -FilterXml @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-TaskScheduler/Operational">
    <Select Path="Microsoft-Windows-TaskScheduler/Operational">
      *[EventData/Data[@Name='TaskName']='$taskPath$taskName']
    </Select>
  </Query>
</QueryList>
"@ -ErrorAction Stop -MaxEvents 10 | Select-Object TimeCreated, Id, @{Name='Message'; Expression = { $_.Message }}
        } catch {
            $history = @("History not available or insufficient permissions")
        }

        # Compile Details
        [PSCustomObject]@{
            Name                                = $taskName
            Author                              = $task.Author
            RunBy                               = $principal # User account running the task
            Description                         = $task.Description
            Location                            = $taskPath
            Triggers                            = $triggers.replace('@{','').replace('}','') -join '; '
            Actions                             = $actions.replace('@{','').replace('}','') -join '; '
            Conditions                          = $conditions
            History                             = $history
            AllowDemandStart                    = $task.Settings.AllowDemandStart
            Enabled                             = $task.Settings.Enabled
            AllowhardTerminate                  = $task.Settings.AllowHardTerminate
            Hidden                              = $task.Settings.Hidden
            Compatibility                       = $task.Settings.Compatibility
            DeleteExpiredTaskAfter              = $task.Settings.DeleteExpiredTaskAfter
            DisallowStartIfOnBatteries          = $task.Settings.DisallowStartIfOnBatteries
            ExecutionTimeLimit                  = $task.Settings.ExecutionTimeLimit
            IdleSettings                        = $task.Settings.IdleSettings
            MultipleInstances                   = $task.Settings.MultipleInstances
            NetworkSettings                     = $task.Settings.NetworkSettings
            Priority                            = $task.Settings.Priority
            RestartCount                        = $task.Settings.RestartCount 
            RestartInterval                     = $task.Settings.RestartInterval
            RunOnlyIfIdle                       = $task.Settings.RunOnlyIfIdle
            RunOnlyIfNetworkAvailable           = $task.Settings.RunOnlyIfNetworkAvailable
            StartWhenAvailable                  = $task.Settings.StartWhenAvailable
            WakeToRun                           = $task.Settings.WakeToRun
            DisallowStartOnRemoteAppSession     = $task.Settings.DisallowStartOnRemoteAppSession
            UseUnifiedSchedulingEngine          = $task.Settings.UseUnifiedSchedulingEngine
            MaintenanceSettings                 = $task.Settings.MaintenanceSettings
            Volatile                            = $task.Settings.Volatile
        }
    }

    # Return all task details
    $tasks
}

# Get all Scheduled Task details and export to a CSV file
$tasksDetails = Get-ScheduledTaskDetails
$tasksDetails | Export-Excel -Path $OuputPathForExcelReport 
