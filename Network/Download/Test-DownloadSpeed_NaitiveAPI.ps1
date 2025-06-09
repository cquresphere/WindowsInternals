#region variables
$Uri = [uri]"http://ipv4.download.thinkbroadband.com:8080/200MB.zip"
$fileName = "200MB.zip"
$destinationFolder = "C:\Temp"
$destinationPath = Join-Path -Path $destinationFolder -ChildPath $fileName
$DownloadMethod = "Naitive .Net API"
$ProgressPreference = 'SilentlyContinue'
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
$PathToCSFile = "$PSScriptRoot\WinHttpHelper.cs"

if(-not-(Test-Path -Path $PathToCSFile)){
    Write-Error "WinHttpHelper.cs is missing!"
}

Add-Type -TypeDefinition (Get-Content -Path $PathToCSFile -Raw)
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
    # Here we open a WinHttp session, connect to the destination host,
    #and open a request to the file.
    $hSession = [Utilities.WinHttp]::WinHttpOpen('NativeDownload', 0, '', '', 0)
    $hConnect = [Utilities.WinHttp]::WinHttpConnect($hSession, $Uri.Host, 80, 0)
    $hRequest = [Utilities.WinHttp]::WinHttpOpenRequest(
        $hConnect, 'GET', $Uri.AbsolutePath, '', '', '', 0
    )

    $stopwatch.Start()
    # Sending the first request.
    $boolResult = [Utilities.WinHttp]::WinHttpSendRequest(
        $hRequest, '', 0, [IntPtr]::Zero, 0, 0, [UIntPtr]::Zero
    )
    if (!$boolResult) {
        Write-Error 'Failed sending request.'
    }
    if (![Utilities.WinHttp]::WinHttpReceiveResponse($hRequest, [IntPtr]::Zero)) {
        Write-Error 'Failed receiving response.'
    }

    $fileStream = [System.IO.FileStream]::new($destinationPath, 'Create')

    # Reading data until there is no more data available.
    do {
        # Querying if there is data available.
        $dwSize = 0
        if (![Utilities.WinHttp]::WinHttpQueryDataAvailable($hRequest, [ref]$dwSize)) {
            Write-Error 'Failed querying for available data.'
        }

        # Allocating memory, and creating the byte array who will hold the managed data.
        $chunk = New-Object -TypeName "System.Byte[]" -ArgumentList $dwSize
        $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($dwSize)

        # Reading the data.
        try {
            $boolResult = [Utilities.WinHttp]::WinHttpReadData(
                $hRequest, $buffer, $dwSize, [ref]$dwSize
            )
            if (!$boolResult) {
                Write-Error 'Failed to read data.'
            }

            # Copying the data from the unmanaged pointer to the managed byte array,
            # then ing the data into the file stream.
            [System.Runtime.InteropServices.Marshal]::Copy($buffer, $chunk, 0, $chunk.Length)
            $fileStream.Write($chunk, 0, $chunk.Length)
        }
        finally {
            # Freeing the unmanaged memory.
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        }

    } while ($dwSize -gt 0)
    $stopwatch.Stop()

    # Closing the unmanaged handles.
    [void][Utilities.WinHttp]::WinHttpCloseHandle($hRequest)
    [void][Utilities.WinHttp]::WinHttpCloseHandle($hConnect)
    [void][Utilities.WinHttp]::WinHttpCloseHandle($hSession)

    # Disposing of the file stream will close the file handle, which will allow us
    # to manage the file later.
    $fileStream.Dispose()
    $fileStream.Dispose()

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
