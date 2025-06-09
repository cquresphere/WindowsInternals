#region variables
# download samples: https://www.thinkbroadband.com/download
$downloadURL = "http://ipv4.download.thinkbroadband.com:8080/200MB.zip"
$fileName = "200MB.zip"
$destinationFolder = "C:\Temp"
$destinationPath = Join-Path -Path $destinationFolder -ChildPath $fileName

$ProgressPreference = 'SilentlyContinue'
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
#endregion variables

#region Procedure
if(-not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder | Out-Null
}

$stopwatch = New-Object -TypeName 'System.Diagnostics.Stopwatch'
$elapsedTime = [timespan]::Zero
$iterationNumber = 3

# Here we are using a foreach loop with a range,
# but this can also be accomplished with a for loop.
foreach ($iteration in 1..$iterationNumber) {

    $stopwatch.Restart()
    Start-BitsTransfer -Source $downloadURL -Destination $destinationPath
    $stopwatch.Stop()

    Remove-Item -Path $destinationPath -Force
    $elapsedTime = $elapsedTime.Add($stopwatch.Elapsed)
}

# Timespan.Divide is not available on .NET Framework.
if ($PSVersionTable.PSVersion -ge [version]'6.0') {
    $average = $elapsedTime.Divide($IterationNumber)
} else { 
    $average = [timespan]::new($elapsedTime.Ticks / $IterationNumber)
}

return $average
