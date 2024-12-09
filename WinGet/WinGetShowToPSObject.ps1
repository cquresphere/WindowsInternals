#variables
$AppID = 'Adobe.Acrobat.Reader.64-bit'  
#region functions
# Define a function to parse the key-value pairs
function Get-KeyValuePairs {
    param (
        [string[]]$Lines,
        [string[]]$Fields
    )
    $result = @{}
    foreach ($line in $Lines) {
        $line = $line.Trim()
        foreach ($field in $Fields) {
            $regex = [regex]::Escape($field) + ":\s*(.+)"
            if ($line -match $regex) {
                $result[$field] = $Matches[1].Trim()
            }
        }
    }
    return $result
}

# Define a function to parse Tags and Installer details
function Get-TagsAndInstaller {
    param (
        [string[]]$Lines
    )
    $tags = @()
    $installerProps = @{}
    $nextLineTags = $false
    $nextLineInstaller = $false

    foreach ($line in $Lines) {
        $line = $line.Trim()
        if ($line -eq "Tags:") {
            $nextLineTags = $true
            $nextLineInstaller = $false
            continue
        }
        elseif ($line -eq "Installer:") {
            $nextLineInstaller = $true
            $nextLineTags = $false
            continue
        }

        if ($nextLineTags) {
            $tags += $line
        }
        elseif ($nextLineInstaller -and $line -match '^\s*(.+?):\s*(.+)$') {
            $key = $Matches[1].Trim()
            $value = $Matches[2].Trim()
            $installerProps[$key] = $value
        }
    }

    return @{ Tags = $tags; Installer = $installerProps }
}
#endregion functions

#region Main Script
$WinGetResponse = winget show --id $AppID --accept-source-agreements

if ($null -ne ($WinGetResponse | Where-Object { $_ -like "*No package found matching input criteria*" })) {
    Write-Host "No package found matching input criteria to ID: $AppID"
}
else {
    # Identify the start of the relevant content
    $FoundIndex = [array]::IndexOf($WinGetResponse, ( $WinGetResponse | Where-Object { $_ -like "*Found*" }))
    if ($WinGetResponse[$FoundIndex] -match '\[(.*?)\]') {
        $AppName = $Matches[1]
    }

    $skippedArray = $WinGetResponse | Select-Object -Skip ($FoundIndex + 1)

    # Define fields to parse
    $Fields = @(
        'Version', 'Publisher', 'Publisher Url', 'Author', 'Moniker', 'Description',
        'Homepage', 'License', 'License Url', 'Privacy Url', 'Copyright', 'Copyright Url'
    )

    # Parse the main fields
    $mainProperties = Get-KeyValuePairs -Lines $skippedArray -Fields $Fields

    # Parse Tags and Installer sections
    $parsedDetails = Get-TagsAndInstaller -Lines $skippedArray
    $tags = $parsedDetails['Tags']
    $installer = $parsedDetails['Installer']

    # Combine results
    $result = $mainProperties + @{
        AppName                      = $AppName
        Tags                         = $tags
        InstallerURL                 = $installer['Installer Url']
        InstallerSHA256              = $installer['Installer SHA256']
        InstallerType                = $installer['Installer Type']
        OfflineDistributionSupported = $installer['Offline Distribution Supported']
    }

    # Convert to PSObject
    $ParsedObject = [PSCustomObject]$result | Select-Object `
        AppName, Version, Publisher, 'Publisher Url', Author, Moniker, Description,
    Homepage, License, 'License Url', 'Privacy Url', Copyright, 'Copyright Url',
    Tags, InstallerSHA256, InstallerURL, InstallerType, OfflineDistributionSupported

    # Output the parsed object
    $ParsedObject
}
#endregion Main Script
