#region variables
$Uri = [uri]"http://ipv4.download.thinkbroadband.com:8080/200MB.zip"
$fileName = "200MB.zip"
$destinationFolder = "C:\Temp"
$destinationPath = Join-Path -Path $destinationFolder -ChildPath $fileName
$DownloadMethod = "Invoke-RestMethod"
$ProgressPreference = 'SilentlyContinue'
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

if(-not-(Test-Path -Path $PathToCSFile)){
    Write-Error "WinHttpHelper.cs is missing!"
}
#endregion variables

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

    $Parameters = @{
	    Uri             = $Uri
        OutFile         = $destinationPath
	    UseBasicParsing = $true
    }

    Invoke-RestMethod @Parameters | Out-Null

    $stopwatch.Stop()
    
    Remove-Item -Path $destinationPath

    $elapsedTime = $elapsedTime.Add($stopwatch.Elapsed)
}
# Timespan.Divide is not available on .NET Framework.
if ($PSVersionTable.PSVersion -ge [version]'6.0') {
    $average = $elapsedTime.Divide($IterationNumber)
} else { 
    $average = [timespan]::new($elapsedTime.Ticks / $IterationNumber)
}

Write-Host "Downloading File: $FileName" -ForegroundColor Cyan
Write-Host "File source: $downloadURL" -ForegroundColor Cyan
Write-Host "with $DownloadMethod" -ForegroundColor Green
Write-Host "Iteration: $iterationNumber" -ForegroundColor Cyan
Write-Host "Average download time:"

return $average
