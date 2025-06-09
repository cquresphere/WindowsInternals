#region variables
$downloadURL = [uri]"http://ipv4.download.thinkbroadband.com:80/200MB.zip"
$fileName = "200MB.zip"
$destinationFolder = "C:\Temp"
$destinationPath = Join-Path -Path $destinationFolder -ChildPath $fileName
$DownloadMethod = "System.Net.HttpClient"
$ProgressPreference = 'SilentlyContinue'
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Net.Http
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

    # Create an instance of HttpClient
    $HttpClient = [System.Net.Http.HttpClient]::new()
    #$HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0")
    $response = $HttpClient.GetAsync($downloadURL).Result

    # Ensure the request was successful
    if ($response.StatusCode -eq 'OK') {
        # Read the file content as a byte array
        $fileBytes = $response.Content.ReadAsByteArrayAsync().Result

        # Save the file to the specified path
        [System.IO.File]::WriteAllBytes($destinationPath, $fileBytes)
        Write-Host "Iteration: $iteration. File downloaded successfully to $destinationPath"
    } 
    elseif($response.StatusCode -eq 'Forbidden'){
        $HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0")
        $response = $HttpClient.GetAsync($downloadURL).Result
        # Read the file content as a byte array
        $fileBytes = $response.Content.ReadAsByteArrayAsync().Result

        # Save the file to the specified path
        [System.IO.File]::WriteAllBytes($destinationPath, $fileBytes)
        Write-Host "Iteration: $iteration. File downloaded successfully to $destinationPath"
    }
    else {
        Write-Host "Failed to download file. Status Code: $($response.StatusCode)"
    }

    # Dispose of the HttpClient instance
    $HttpClient.Dispose()

    $stopwatch.Stop()
    
    Remove-Item -Path $destinationPath -Force

    $elapsedTime = $elapsedTime.Add($stopwatch.Elapsed)
}

$average = $null
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
