<#

.SYNOPSIS
Resolves winget community manifest metadata (installer URLs and SHA256 hashes) for a package.

.DESCRIPTION
Reads the microsoft/winget-pkgs repository over HTTPS and returns normalized metadata for the
latest (or a pinned) version of a package, identified by winget Package Identifier or Moniker.

The script is both a standalone tool and a dot-sourceable library. Dot-sourcing only defines the
functions; it does not execute the entry point.

Improvements over an inline per-template implementation:

- Root-level manifest fields are inherited by each installer entry, as the winget schema requires.
  Many manifests declare Scope / InstallerType / InstallerSwitches only at the root, so reading
  the installer entries alone loses that data.
- Nested installers (InstallerType: zip + NestedInstallerType) are surfaced explicitly, including
  the relative file path inside the archive.
- Manifest file names are discovered from the repository listing instead of being guessed, so
  singleton manifests and non-en-US default locales work.
- Version ordering does not depend on [Version] parsing, so date-style and suffixed versions
  (2026.01.05, 1.2.3-beta) sort correctly. Pre-release versions are excluded by default.
- GitHub rate limiting is detected and reported with the reset time instead of surfacing as an
  opaque failure. An optional token raises the limit from 60 to 5000 requests/hour.

.PARAMETER PackageIdentifier
The winget package identifier, for example 'TeamViewer.TeamViewer.Host'.

.PARAMETER Moniker
The winget moniker, for example 'teamviewer-host'. Resolved to a package identifier using the
Microsoft.WinGet.Client module or winget.exe.

.PARAMETER Version
Pin a specific package version. Defaults to the newest version found.

.PARAMETER Architecture
Return only installers for this architecture (x64, x86, arm64, arm, neutral).

.PARAMETER Scope
Return only installers for this scope (machine, user).

.PARAMETER InstallerType
Return only installers of this effective type (exe, msi, wix, nullsoft, inno, burn, msix, zip...).
Matching is done against the nested type for archive installers.

.PARAMETER UrlLike
Return only installers whose InstallerUrl matches this wildcard pattern, for example '*Setup*'.

.PARAMETER IncludePrerelease
Consider versions that look like pre-releases (a hyphen followed by letters, e.g. 1.2.0-beta).

.PARAMETER ListVersions
Return the available version list instead of the full manifest.

.PARAMETER SkipLocale
Skip the locale manifest fetch. Saves one request; omits publisher/description/license fields.

.PARAMETER GitHubToken
GitHub token used to raise the API rate limit. Defaults to $env:GITHUB_TOKEN when present.

.PARAMETER Branch
Branch of the winget-pkgs repository to read. Defaults to 'master'.

.PARAMETER AsJson
Emit JSON instead of objects.

.PARAMETER OutFile
Write the result (JSON) to this path in addition to returning it.

.EXAMPLE
.\WingetManifestMetadata.ps1 -PackageIdentifier TeamViewer.TeamViewer.Host

.EXAMPLE
.\WingetManifestMetadata.ps1 -Moniker teamviewer-host -Architecture x64 -InstallerType nullsoft

.EXAMPLE
.\WingetManifestMetadata.ps1 -PackageIdentifier 7zip.7zip -AsJson -OutFile .\7zip.json

.EXAMPLE
$m = .\WingetManifestMetadata.ps1 -PackageIdentifier Mozilla.Firefox
$m.Installers | Select-Object Architecture, EffectiveInstallerType, InstallerUrl, InstallerSha256

.EXAMPLE
# Library use from a deployment script.
. "$PSScriptRoot\SupportFiles\WingetManifestMetadata.ps1"
$manifest = Get-WingetPackageManifest -PackageIdentifier 'TeamViewer.TeamViewer.Host'
$installer = Select-WingetInstaller -Manifest $manifest -Architecture x64 -InstallerType nullsoft -First
$installer.InstallerUrl
$installer.InstallerSha256

.NOTES
Author : Karol Kula
Requires: PowerShell 5.1+, network access to api.github.com and raw.githubusercontent.com.
YAML parsing uses the powershell-yaml module; it is imported if present and installed on demand.

.LINK
https://github.com/microsoft/winget-pkgs

#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false, Position = 0)]
    [String]$PackageIdentifier,

    [Parameter(Mandatory = $false)]
    [String]$Moniker,

    [Parameter(Mandatory = $false)]
    [String]$Version,

    [Parameter(Mandatory = $false)]
    [ValidateSet('x64', 'x86', 'arm64', 'arm', 'neutral')]
    [String]$Architecture,

    [Parameter(Mandatory = $false)]
    [ValidateSet('machine', 'user')]
    [String]$Scope,

    [Parameter(Mandatory = $false)]
    [String]$InstallerType,

    [Parameter(Mandatory = $false)]
    [String]$UrlLike,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter]$IncludePrerelease,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter]$ListVersions,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter]$SkipLocale,

    [Parameter(Mandatory = $false)]
    [String]$GitHubToken,

    [Parameter(Mandatory = $false)]
    [String]$Branch = 'master',

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter]$AsJson,

    [Parameter(Mandatory = $false)]
    [String]$OutFile
)

##================================================
## MARK: Module state
##================================================

$script:WingetRepository = 'microsoft/winget-pkgs'
$script:WingetUserAgent = 'WingetManifestMetadata/1.0 (+PSAppDeployToolkit)'
$script:WingetApiRoot = 'https://api.github.com'
$script:WingetYamlReady = $false

# Fields the winget installer schema allows at the manifest root and inherits into each installer
# entry unless the entry overrides them. Losing these is the most common source of wrong metadata:
# 'Scope' and 'InstallerType' in particular are frequently declared only at the root.
$script:WingetInheritableInstallerFields = @(
    'InstallerLocale'
    'Platform'
    'MinimumOSVersion'
    'InstallerType'
    'NestedInstallerType'
    'NestedInstallerFiles'
    'Scope'
    'InstallModes'
    'InstallerSwitches'
    'InstallerSuccessCodes'
    'ExpectedReturnCodes'
    'UpgradeBehavior'
    'Commands'
    'Protocols'
    'FileExtensions'
    'Dependencies'
    'PackageFamilyName'
    'ProductCode'
    'Capabilities'
    'RestrictedCapabilities'
    'Markets'
    'InstallerAbortsTerminal'
    'ReleaseDate'
    'InstallLocationRequired'
    'RequireExplicitUpgrade'
    'DisplayInstallWarnings'
    'ElevationRequirement'
    'UnsupportedOSArchitectures'
    'UnsupportedArguments'
    'AppsAndFeaturesEntries'
    'InstallationMetadata'
    'DownloadCommandProhibited'
    'RepairBehavior'
    'ArchiveBinariesDependOnPath'
    'Authentication'
)

##================================================
## MARK: Low level helpers
##================================================

function Initialize-WingetTls
{
    [CmdletBinding()]
    param
    (
    )

    if ($PSVersionTable.PSVersion.Major -ge 6)
    {
        return
    }

    try
    {
        $current = [System.Net.ServicePointManager]::SecurityProtocol
        if (($current -band [System.Net.SecurityProtocolType]::Tls12) -eq 0)
        {
            [System.Net.ServicePointManager]::SecurityProtocol = $current -bor [System.Net.SecurityProtocolType]::Tls12
        }
    }
    catch
    {
        Write-Verbose "Unable to enforce TLS 1.2. $($_.Exception.Message)"
    }
}

function Initialize-WingetYamlParser
{
    <#
    .SYNOPSIS
    Ensures ConvertFrom-Yaml is available, importing or installing powershell-yaml if needed.
    #>
    [CmdletBinding()]
    param
    (
    )

    if ($script:WingetYamlReady -and (Get-Command -Name ConvertFrom-Yaml -ErrorAction SilentlyContinue))
    {
        return
    }

    if (Get-Command -Name ConvertFrom-Yaml -ErrorAction SilentlyContinue)
    {
        $script:WingetYamlReady = $true
        return
    }

    if (Get-Module -ListAvailable -Name powershell-yaml)
    {
        Import-Module powershell-yaml -ErrorAction Stop
        $script:WingetYamlReady = $true
        return
    }

    Initialize-WingetTls
    Write-Verbose 'powershell-yaml is not present. Attempting installation from PSGallery.'

    try
    {
        if ((Get-Command -Name Get-PackageProvider -ErrorAction SilentlyContinue) -and
            -not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue))
        {
            Install-PackageProvider -Name NuGet -MinimumVersion '2.8.5.201' -Force -ErrorAction Stop | Out-Null
        }
    }
    catch
    {
        Write-Verbose "Unable to bootstrap the NuGet package provider. $($_.Exception.Message)"
    }

    $isElevated = $false
    try
    {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        if ($identity)
        {
            $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
            $isElevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        }
    }
    catch
    {
        $isElevated = $false
    }

    $scopes = @('CurrentUser')
    if ($isElevated)
    {
        $scopes = @('AllUsers', 'CurrentUser')
    }

    foreach ($installScope in $scopes)
    {
        try
        {
            Install-Module -Name powershell-yaml -Repository PSGallery -Scope $installScope -Force -AllowClobber -ErrorAction Stop
            Import-Module powershell-yaml -ErrorAction Stop
            if (Get-Command -Name ConvertFrom-Yaml -ErrorAction SilentlyContinue)
            {
                $script:WingetYamlReady = $true
                return
            }
        }
        catch
        {
            Write-Verbose "powershell-yaml install failed for scope [$installScope]. $($_.Exception.Message)"
        }
    }

    throw 'ConvertFrom-Yaml is unavailable and the powershell-yaml module could not be installed. Install it manually with: Install-Module powershell-yaml -Scope CurrentUser'
}

function Get-WingetResponseHeader
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [Object]$Response,

        [Parameter(Mandatory = $true)]
        [String]$Name
    )

    if (-not $Response)
    {
        return ''
    }

    try
    {
        $headers = $Response.Headers
        if (-not $headers)
        {
            return ''
        }

        # Windows PowerShell exposes WebHeaderCollection; PowerShell 7 exposes HttpResponseHeaders.
        if ($headers -is [System.Net.WebHeaderCollection])
        {
            return [String]$headers[$Name]
        }

        $values = $null
        if ($headers.PSObject.Methods['TryGetValues'] -and $headers.TryGetValues($Name, [ref]$values))
        {
            return [String]@($values)[0]
        }

        return [String]@($headers[$Name])[0]
    }
    catch
    {
        return ''
    }
}

function Get-WingetResponseText
{
    <#
    .SYNOPSIS
    Reads a web response body as UTF-8, avoiding the codepage guessing done by Invoke-WebRequest.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Object]$Response
    )

    try
    {
        $stream = $Response.RawContentStream
        if ($stream -and $stream.CanSeek)
        {
            $stream.Position = 0
            $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8, $true, 4096, $true)
            try
            {
                $text = $reader.ReadToEnd()
            }
            finally
            {
                $reader.Dispose()
            }

            if (-not [String]::IsNullOrEmpty($text))
            {
                return $text
            }
        }
    }
    catch
    {
        Write-Verbose "Falling back to Response.Content. $($_.Exception.Message)"
    }

    return [String]$Response.Content
}

function Invoke-WingetWebRequest
{
    <#
    .SYNOPSIS
    HTTPS GET with retry, GitHub rate-limit detection, and no retry on 404.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$Uri,

        [Parameter(Mandatory = $false)]
        [String]$GitHubToken = '',

        [Parameter(Mandatory = $false)]
        [Int32]$MaxRetries = 4,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$ApiRequest
    )

    Initialize-WingetTls

    $headers = @{ 'User-Agent' = $script:WingetUserAgent }
    if ($ApiRequest)
    {
        $headers['Accept'] = 'application/vnd.github+json'
        $headers['X-GitHub-Api-Version'] = '2022-11-28'
    }
    if (-not [String]::IsNullOrWhiteSpace($GitHubToken))
    {
        $headers['Authorization'] = "Bearer $($GitHubToken.Trim())"
    }

    $attempt = 1
    while ($true)
    {
        try
        {
            return Invoke-WebRequest -Uri $Uri -Headers $headers -UseBasicParsing -ErrorAction Stop
        }
        catch
        {
            $errorRecord = $_
            $statusCode = 0
            $webResponse = $null

            try
            {
                $webResponse = $errorRecord.Exception.Response
            }
            catch
            {
                $webResponse = $null
            }

            if ($webResponse)
            {
                try
                {
                    $statusCode = [Int32]$webResponse.StatusCode
                }
                catch
                {
                    $statusCode = 0
                }
            }

            if ($statusCode -eq 404)
            {
                throw "Not found (HTTP 404): [$Uri]. Note that paths in the winget-pkgs repository are case sensitive."
            }

            $rateLimitRemaining = Get-WingetResponseHeader -Response $webResponse -Name 'X-RateLimit-Remaining'
            $isRateLimited = (($statusCode -eq 403) -or ($statusCode -eq 429)) -and ($rateLimitRemaining -eq '0')

            if ($isRateLimited)
            {
                $resetText = 'unknown'
                $resetEpoch = 0
                if ([Int64]::TryParse((Get-WingetResponseHeader -Response $webResponse -Name 'X-RateLimit-Reset'), [ref]$resetEpoch) -and ($resetEpoch -gt 0))
                {
                    $resetText = ([System.DateTimeOffset]::FromUnixTimeSeconds($resetEpoch)).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
                }

                $tokenHint = 'Supply -GitHubToken (or set $env:GITHUB_TOKEN) to raise the limit from 60 to 5000 requests per hour.'
                if (-not [String]::IsNullOrWhiteSpace($GitHubToken))
                {
                    $tokenHint = 'The supplied GitHub token has exhausted its quota.'
                }

                throw "GitHub API rate limit exceeded for [$Uri]. Limit resets at [$resetText]. $tokenHint"
            }

            $isRetryable = ($statusCode -eq 0) -or ($statusCode -eq 429) -or ($statusCode -ge 500)
            if (-not $isRetryable -or ($attempt -ge $MaxRetries))
            {
                throw "Request failed for [$Uri] (HTTP $statusCode) after $attempt attempt(s). $($errorRecord.Exception.Message)"
            }

            $delaySeconds = [Math]::Min(30, [Math]::Pow(2, $attempt))
            $retryAfter = 0
            if ([Int32]::TryParse((Get-WingetResponseHeader -Response $webResponse -Name 'Retry-After'), [ref]$retryAfter) -and ($retryAfter -gt 0))
            {
                $delaySeconds = [Math]::Min(60, $retryAfter)
            }

            Write-Verbose "Attempt $attempt failed (HTTP $statusCode) for [$Uri]. Retrying in $delaySeconds second(s)."
            Start-Sleep -Seconds $delaySeconds
            $attempt++
        }
    }
}

function Invoke-WingetGitHubApi
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$Uri,

        [Parameter(Mandatory = $false)]
        [String]$GitHubToken = ''
    )

    $response = Invoke-WingetWebRequest -Uri $Uri -GitHubToken $GitHubToken -ApiRequest
    return (Get-WingetResponseText -Response $response | ConvertFrom-Json)
}

function Get-WingetYamlValue
{
    <#
    .SYNOPSIS
    Reads a key from a parsed YAML node, which may be a hashtable or a PSCustomObject.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [Object]$Node,

        [Parameter(Mandatory = $true)]
        [String]$Name
    )

    if ($null -eq $Node)
    {
        return $null
    }

    if ($Node -is [System.Collections.IDictionary])
    {
        if ($Node.Contains($Name))
        {
            return $Node[$Name]
        }
        return $null
    }

    $property = $Node.PSObject.Properties[$Name]
    if ($property)
    {
        return $property.Value
    }
    return $null
}

function Test-WingetYamlValue
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [Object]$Node,

        [Parameter(Mandatory = $true)]
        [String]$Name
    )

    $value = Get-WingetYamlValue -Node $Node -Name $Name
    if ($null -eq $value)
    {
        return $false
    }
    if (($value -is [String]) -and [String]::IsNullOrWhiteSpace($value))
    {
        return $false
    }
    return $true
}

##================================================
## MARK: Version handling
##================================================

function ConvertTo-WingetVersionInfo
{
    <#
    .SYNOPSIS
    Splits a version string into comparable segments without relying on [Version] parsing.

    .DESCRIPTION
    winget versions are free-form strings. Date versions (2026.08.11), five-part versions and
    suffixed versions (1.2.3-beta) are all valid and none of them round-trip through [Version].
    A version is treated as a pre-release when a hyphen is followed by a letter.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$VersionString
    )

    $raw = ''
    if ($null -ne $VersionString)
    {
        $raw = $VersionString.Trim()
    }

    $work = $raw -replace '^[vV](?=\d)', ''
    $rawSegments = @($work -split '[.\-_+]' | Where-Object { -not [String]::IsNullOrWhiteSpace($_) })

    # Split mixed segments at digit/letter boundaries so 'rc10' outranks 'rc2' instead of being
    # compared as one opaque token.
    $segmentList = New-Object System.Collections.Generic.List[String]
    foreach ($rawSegment in $rawSegments)
    {
        foreach ($part in [System.Text.RegularExpressions.Regex]::Matches($rawSegment, '\d+|\D+'))
        {
            $text = [String]$part.Value
            if (-not [String]::IsNullOrWhiteSpace($text))
            {
                [void]$segmentList.Add($text)
            }
        }
    }

    $segments = @($segmentList)
    $isPrerelease = [bool]($raw -match '-\s*[A-Za-z]')

    return [PSCustomObject]@{
        Raw = $raw
        Segments = $segments
        IsPrerelease = $isPrerelease
    }
}

function Get-WingetVersionSortKey
{
    <#
    .SYNOPSIS
    Builds a fixed-width alphanumeric key so version ordering is a plain string sort.

    .DESCRIPTION
    Each segment becomes 21 characters: a leading '1' for numeric segments and '0' for
    non-numeric ones, so a numeric segment always outranks a textual one at the same position
    (1.0.0 is newer than 1.0.0-rc). Absent segments are zero-filled, which makes 1.2 equal to
    1.2.0. A trailing flag ranks releases above pre-releases.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$VersionString,

        [Parameter(Mandatory = $false)]
        [Int32]$SegmentCount = 12,

        [Parameter(Mandatory = $false)]
        [Int32]$SegmentWidth = 20
    )

    $info = ConvertTo-WingetVersionInfo -VersionString $VersionString
    $builder = New-Object System.Text.StringBuilder

    for ($index = 0; $index -lt $SegmentCount; $index++)
    {
        $segment = ''
        if ($index -lt $info.Segments.Count)
        {
            $segment = [String]$info.Segments[$index]
        }

        if ([String]::IsNullOrEmpty($segment) -or ($segment -match '^\d+$'))
        {
            # Absent segments compare equal to an explicit zero.
            [void]$builder.Append('1').Append($segment.PadLeft($SegmentWidth, '0'))
        }
        else
        {
            $normalized = ($segment.ToLowerInvariant() -replace '[^0-9a-z]', '0')
            if ($normalized.Length -gt $SegmentWidth)
            {
                $normalized = $normalized.Substring(0, $SegmentWidth)
            }
            [void]$builder.Append('0').Append($normalized.PadRight($SegmentWidth, '0'))
        }
    }

    if ($info.IsPrerelease)
    {
        [void]$builder.Append('0')
    }
    else
    {
        [void]$builder.Append('1')
    }

    return $builder.ToString()
}

function Compare-WingetVersion
{
    <#
    .SYNOPSIS
    Returns -1, 0 or 1 comparing two winget version strings.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$ReferenceVersion,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$DifferenceVersion
    )

    $left = Get-WingetVersionSortKey -VersionString $ReferenceVersion
    $right = Get-WingetVersionSortKey -VersionString $DifferenceVersion
    $result = [String]::CompareOrdinal($left, $right)

    if ($result -lt 0)
    {
        return -1
    }
    if ($result -gt 0)
    {
        return 1
    }
    return 0
}

##================================================
## MARK: Package identity
##================================================

function Get-WingetManifestPath
{
    <#
    .SYNOPSIS
    Maps a package identifier to its path inside the winget-pkgs repository.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$PackageIdentifier
    )

    if ([String]::IsNullOrWhiteSpace($PackageIdentifier))
    {
        throw 'PackageIdentifier is required.'
    }

    $trimmed = $PackageIdentifier.Trim()
    if ($trimmed -match '[\\/:\*\?"<>\|]')
    {
        throw "Package identifier [$trimmed] contains characters that are not valid in a winget identifier."
    }

    $segments = @($trimmed -split '\.' | Where-Object { -not [String]::IsNullOrWhiteSpace($_) })
    if ($segments.Count -lt 2)
    {
        throw "Package identifier [$trimmed] is not valid. Expected at least Publisher.Package, for example 'TeamViewer.TeamViewer.Host'."
    }

    $bucket = $segments[0].Substring(0, 1).ToLowerInvariant()
    return ('manifests/{0}/{1}' -f $bucket, ([String]::Join('/', $segments)))
}

function Resolve-WingetPackageIdentifier
{
    <#
    .SYNOPSIS
    Resolves a moniker (or a case-inexact identifier) to the canonical package identifier.

    .DESCRIPTION
    Tries the Microsoft.WinGet.Client module first because it returns objects, then falls back to
    parsing the '[Id]' token from the first line of winget.exe show output. That token is not
    localized, so the fallback is safe on non-English hosts.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [String]$Moniker,

        [Parameter(Mandatory = $false)]
        [String]$PackageIdentifier
    )

    $useMoniker = -not [String]::IsNullOrWhiteSpace($Moniker)
    $query = if ($useMoniker) { $Moniker.Trim() } else { $PackageIdentifier.Trim() }
    $label = if ($useMoniker) { "moniker [$query]" } else { "identifier [$query]" }

    if ([String]::IsNullOrWhiteSpace($query))
    {
        throw 'Either Moniker or PackageIdentifier must be supplied.'
    }

    # Tier 1: the WinGet client module returns structured results.
    try
    {
        if (Get-Module -ListAvailable -Name Microsoft.WinGet.Client)
        {
            Import-Module Microsoft.WinGet.Client -ErrorAction Stop

            $found = if ($useMoniker)
            {
                @(Find-WinGetPackage -Moniker $query -Source winget -MatchOption Equals -ErrorAction Stop)
            }
            else
            {
                @(Find-WinGetPackage -Id $query -Source winget -MatchOption EqualsCaseInsensitive -ErrorAction Stop)
            }

            $match = @($found | Where-Object { -not [String]::IsNullOrWhiteSpace($_.Id) })
            if ($match.Count -gt 0)
            {
                if ($match.Count -gt 1)
                {
                    Write-Verbose "Multiple packages matched $label. Using [$($match[0].Id)]."
                }
                return [String]$match[0].Id
            }
        }
    }
    catch
    {
        Write-Verbose "Microsoft.WinGet.Client lookup failed for $label. $($_.Exception.Message)"
    }

    # Tier 2: winget.exe. The first output line reads 'Found <Name> [<Id>]'; only the brackets matter.
    try
    {
        if (Get-Command -Name winget -ErrorAction SilentlyContinue)
        {
            $arguments = if ($useMoniker) { @('--moniker', $query) } else { @('--id', $query) }
            $output = @(& winget show @arguments --exact --source winget --disable-interactivity 2>$null)
            $firstLine = @($output | Where-Object { -not [String]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)

            if ($firstLine.Count -gt 0 -and ($firstLine[0] -match '\[(?<id>[^\[\]]+)\]\s*$'))
            {
                return [String]$Matches['id']
            }
        }
    }
    catch
    {
        Write-Verbose "winget.exe lookup failed for $label. $($_.Exception.Message)"
    }

    if ($useMoniker)
    {
        throw "Unable to resolve $label to a package identifier. Moniker lookup needs the winget client (Microsoft.WinGet.Client module or winget.exe), which is not usable on this host. Pass -PackageIdentifier instead."
    }

    # For an identifier, an unresolved lookup is not fatal; the repository path may still be correct.
    Write-Verbose "Unable to canonicalize $label with the winget client. Using the supplied value."
    return $query
}

##================================================
## MARK: Repository reads
##================================================

function Get-WingetPackageVersion
{
    <#
    .SYNOPSIS
    Lists the versions published for a package, newest first.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$PackageIdentifier,

        [Parameter(Mandatory = $false)]
        [String]$Branch = 'master',

        [Parameter(Mandatory = $false)]
        [String]$GitHubToken = ''
    )

    $manifestPath = Get-WingetManifestPath -PackageIdentifier $PackageIdentifier
    $uri = '{0}/repos/{1}/contents/{2}?ref={3}' -f $script:WingetApiRoot, $script:WingetRepository, $manifestPath, $Branch

    Write-Verbose "Listing versions from [$uri]."
    $entries = @(Invoke-WingetGitHubApi -Uri $uri -GitHubToken $GitHubToken)

    # Version folder names always start with a digit; this also filters out .validation and similar.
    $versionEntries = @(
        $entries |
            Where-Object { $_.type -eq 'dir' } |
            Where-Object { [String]$_.name -match '^\d' }
    )

    if ($versionEntries.Count -eq 0)
    {
        throw "No version folders found for [$PackageIdentifier] under [$manifestPath]."
    }

    $versions = @(
        $versionEntries | ForEach-Object {
            $name = [String]$_.name
            $info = ConvertTo-WingetVersionInfo -VersionString $name
            [PSCustomObject]@{
                Version = $name
                IsPrerelease = $info.IsPrerelease
                Path = "$manifestPath/$name"
                SortKey = Get-WingetVersionSortKey -VersionString $name
            }
        }
    )

    return @($versions | Sort-Object -Property SortKey -Descending)
}

function Select-WingetTargetVersion
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Object[]]$AvailableVersions,

        [Parameter(Mandatory = $false)]
        [String]$Version = '',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$IncludePrerelease
    )

    if ($AvailableVersions.Count -eq 0)
    {
        throw 'No versions available to select from.'
    }

    if (-not [String]::IsNullOrWhiteSpace($Version))
    {
        $requested = $Version.Trim()
        $exact = @($AvailableVersions | Where-Object { $_.Version -eq $requested })
        if ($exact.Count -eq 0)
        {
            $exact = @($AvailableVersions | Where-Object { $_.Version -like $requested })
        }
        if ($exact.Count -eq 0)
        {
            $sample = [String]::Join(', ', @($AvailableVersions | Select-Object -First 10 -ExpandProperty Version))
            throw "Version [$requested] was not found. Available versions include: $sample"
        }
        return @($exact)[0]
    }

    $candidates = @($AvailableVersions)
    if (-not $IncludePrerelease)
    {
        $stable = @($AvailableVersions | Where-Object { -not $_.IsPrerelease })
        if ($stable.Count -gt 0)
        {
            $candidates = $stable
        }
        else
        {
            Write-Verbose 'Every published version looks like a pre-release. Falling back to the full set.'
        }
    }

    return @($candidates)[0]
}

function ConvertTo-WingetInstallerObject
{
    <#
    .SYNOPSIS
    Normalizes one installer entry, applying root-level inheritance.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Object]$Installer,

        [Parameter(Mandatory = $true)]
        [Object]$Root
    )

    # Inherit any root-level field the entry does not define itself.
    $merged = [ordered]@{}
    foreach ($field in $script:WingetInheritableInstallerFields)
    {
        $value = Get-WingetYamlValue -Node $Installer -Name $field
        if ($null -eq $value)
        {
            $value = Get-WingetYamlValue -Node $Root -Name $field
        }
        $merged[$field] = $value
    }

    foreach ($field in @('Architecture', 'InstallerUrl', 'InstallerSha256', 'SignatureSha256', 'InstallerLocale'))
    {
        $direct = Get-WingetYamlValue -Node $Installer -Name $field
        if ($null -ne $direct)
        {
            $merged[$field] = $direct
        }
        elseif (-not $merged.Contains($field))
        {
            $merged[$field] = Get-WingetYamlValue -Node $Root -Name $field
        }
    }

    $installerType = [String]$merged['InstallerType']
    $nestedType = [String]$merged['NestedInstallerType']
    $isNested = (-not [String]::IsNullOrWhiteSpace($nestedType)) -and ($installerType -eq 'zip')

    # For an archive the type that matters to a deployment is what is inside it, not 'zip'.
    $effectiveType = $installerType
    if ($isNested)
    {
        $effectiveType = $nestedType
    }

    $nestedFiles = @(
        @($merged['NestedInstallerFiles']) | Where-Object { $null -ne $_ } | ForEach-Object {
            [PSCustomObject]@{
                RelativeFilePath = [String](Get-WingetYamlValue -Node $_ -Name 'RelativeFilePath')
                PortableCommandAlias = [String](Get-WingetYamlValue -Node $_ -Name 'PortableCommandAlias')
            }
        }
    )

    $appsAndFeatures = @(
        @($merged['AppsAndFeaturesEntries']) | Where-Object { $null -ne $_ } | ForEach-Object {
            [PSCustomObject]@{
                DisplayName = [String](Get-WingetYamlValue -Node $_ -Name 'DisplayName')
                DisplayVersion = [String](Get-WingetYamlValue -Node $_ -Name 'DisplayVersion')
                Publisher = [String](Get-WingetYamlValue -Node $_ -Name 'Publisher')
                ProductCode = [String](Get-WingetYamlValue -Node $_ -Name 'ProductCode')
                UpgradeCode = [String](Get-WingetYamlValue -Node $_ -Name 'UpgradeCode')
                InstallerType = [String](Get-WingetYamlValue -Node $_ -Name 'InstallerType')
            }
        }
    )

    $upgradeCode = ''
    $upgradeCodeEntry = @($appsAndFeatures | Where-Object { -not [String]::IsNullOrWhiteSpace($_.UpgradeCode) })
    if ($upgradeCodeEntry.Count -gt 0)
    {
        $upgradeCode = $upgradeCodeEntry[0].UpgradeCode
    }

    $installerUrl = [String]$merged['InstallerUrl']
    $fileName = ''
    if (-not [String]::IsNullOrWhiteSpace($installerUrl))
    {
        try
        {
            $fileName = [System.IO.Path]::GetFileName(([System.Uri]$installerUrl).AbsolutePath)
        }
        catch
        {
            $fileName = Split-Path -Path (($installerUrl -split '\?')[0]) -Leaf
        }
    }

    # Manifests are inconsistent about hash casing; normalize so comparisons are trivial.
    $sha256 = [String]$merged['InstallerSha256']
    if (-not [String]::IsNullOrWhiteSpace($sha256))
    {
        $sha256 = $sha256.Trim().ToUpperInvariant()
    }

    $switches = $merged['InstallerSwitches']
    $switchObject = $null
    if ($switches)
    {
        $switchObject = [PSCustomObject]@{
            Silent = [String](Get-WingetYamlValue -Node $switches -Name 'Silent')
            SilentWithProgress = [String](Get-WingetYamlValue -Node $switches -Name 'SilentWithProgress')
            Interactive = [String](Get-WingetYamlValue -Node $switches -Name 'Interactive')
            InstallLocation = [String](Get-WingetYamlValue -Node $switches -Name 'InstallLocation')
            Log = [String](Get-WingetYamlValue -Node $switches -Name 'Log')
            Upgrade = [String](Get-WingetYamlValue -Node $switches -Name 'Upgrade')
            Custom = [String](Get-WingetYamlValue -Node $switches -Name 'Custom')
            Repair = [String](Get-WingetYamlValue -Node $switches -Name 'Repair')
        }
    }

    return [PSCustomObject]@{
        Architecture = [String]$merged['Architecture']
        InstallerType = $installerType
        NestedInstallerType = $nestedType
        EffectiveInstallerType = $effectiveType
        IsNested = $isNested
        NestedInstallerFiles = $nestedFiles
        NestedRelativeFilePath = if ($nestedFiles.Count -gt 0) { $nestedFiles[0].RelativeFilePath } else { '' }
        Scope = [String]$merged['Scope']
        InstallerUrl = $installerUrl
        InstallerSha256 = $sha256
        SignatureSha256 = [String]$merged['SignatureSha256']
        FileName = $fileName
        ProductCode = [String]$merged['ProductCode']
        UpgradeCode = $upgradeCode
        PackageFamilyName = [String]$merged['PackageFamilyName']
        InstallerLocale = [String]$merged['InstallerLocale']
        MinimumOSVersion = [String]$merged['MinimumOSVersion']
        Platform = @($merged['Platform'] | Where-Object { $null -ne $_ } | ForEach-Object { [String]$_ })
        InstallerSwitches = $switchObject
        InstallerSuccessCodes = @($merged['InstallerSuccessCodes'] | Where-Object { $null -ne $_ })
        UpgradeBehavior = [String]$merged['UpgradeBehavior']
        ElevationRequirement = [String]$merged['ElevationRequirement']
        ReleaseDate = [String]$merged['ReleaseDate']
        AppsAndFeaturesEntries = $appsAndFeatures
        DownloadCommandProhibited = [bool]$merged['DownloadCommandProhibited']
    }
}

function Get-WingetPackageManifest
{
    <#
    .SYNOPSIS
    Returns normalized metadata for one version of a winget package.

    .DESCRIPTION
    Discovers the manifest file names from the repository listing rather than guessing them, which
    keeps singleton manifests and non-en-US default locales working. Costs two GitHub API calls
    plus two or three raw file reads (raw reads do not consume the API rate limit).
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$PackageIdentifier,

        [Parameter(Mandatory = $false)]
        [String]$Version = '',

        [Parameter(Mandatory = $false)]
        [String]$Branch = 'master',

        [Parameter(Mandatory = $false)]
        [String]$GitHubToken = '',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$IncludePrerelease,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$SkipLocale
    )

    Initialize-WingetYamlParser

    $identifier = $PackageIdentifier.Trim()
    $availableVersions = $null

    try
    {
        $availableVersions = @(Get-WingetPackageVersion -PackageIdentifier $identifier -Branch $Branch -GitHubToken $GitHubToken)
    }
    catch
    {
        # A 404 here is usually a casing mismatch, since repository paths are case sensitive.
        if ($_.Exception.Message -notmatch 'HTTP 404|Not found')
        {
            throw
        }

        $canonical = Resolve-WingetPackageIdentifier -PackageIdentifier $identifier

        # Ordinal comparison on purpose: -eq is case insensitive, and casing is the whole point here.
        if ([String]::Equals($canonical, $identifier, [System.StringComparison]::Ordinal))
        {
            throw "Package [$identifier] was not found in the winget-pkgs repository. Repository paths are case sensitive; verify the exact identifier with 'winget search $identifier'."
        }

        Write-Verbose "Retrying with canonical identifier [$canonical]."
        $identifier = $canonical
        $availableVersions = @(Get-WingetPackageVersion -PackageIdentifier $identifier -Branch $Branch -GitHubToken $GitHubToken)
    }

    $target = Select-WingetTargetVersion -AvailableVersions $availableVersions -Version $Version -IncludePrerelease:$IncludePrerelease
    $manifestPath = Get-WingetManifestPath -PackageIdentifier $identifier

    $listUri = '{0}/repos/{1}/contents/{2}/{3}?ref={4}' -f $script:WingetApiRoot, $script:WingetRepository, $manifestPath, $target.Version, $Branch
    Write-Verbose "Listing manifest files from [$listUri]."

    $files = @(
        @(Invoke-WingetGitHubApi -Uri $listUri -GitHubToken $GitHubToken) |
            Where-Object { $_.type -eq 'file' } |
            Where-Object { [String]$_.name -match '\.ya?ml$' }
    )

    if ($files.Count -eq 0)
    {
        throw "No manifest files found for [$identifier] version [$($target.Version)]."
    }

    $installerFile = @($files | Where-Object { [String]$_.name -like '*.installer.yaml' })
    $localeFiles = @($files | Where-Object { [String]$_.name -like '*.locale.*.yaml' })
    $versionFile = @($files | Where-Object { ([String]$_.name -notlike '*.installer.yaml') -and ([String]$_.name -notlike '*.locale.*.yaml') })

    $sourceUris = New-Object System.Collections.Generic.List[String]

    function Get-WingetManifestDocument
    {
        param
        (
            [Parameter(Mandatory = $true)]
            [Object]$FileEntry
        )

        $downloadUrl = [String]$FileEntry.download_url
        if ([String]::IsNullOrWhiteSpace($downloadUrl))
        {
            throw "Manifest listing entry [$($FileEntry.name)] has no download_url."
        }

        Write-Verbose "Reading manifest [$downloadUrl]."
        $response = Invoke-WingetWebRequest -Uri $downloadUrl -GitHubToken $GitHubToken
        $text = Get-WingetResponseText -Response $response
        [void]$sourceUris.Add($downloadUrl)
        return ($text | ConvertFrom-Yaml)
    }

    $installerDocument = $null
    $versionDocument = $null
    $isSingleton = $false

    if ($installerFile.Count -gt 0)
    {
        $installerDocument = Get-WingetManifestDocument -FileEntry $installerFile[0]
    }

    if ($versionFile.Count -gt 0)
    {
        $versionDocument = Get-WingetManifestDocument -FileEntry $versionFile[0]
        if ([String](Get-WingetYamlValue -Node $versionDocument -Name 'ManifestType') -eq 'singleton')
        {
            $isSingleton = $true
            if ($null -eq $installerDocument)
            {
                $installerDocument = $versionDocument
            }
        }
    }

    if ($null -eq $installerDocument)
    {
        throw "No installer manifest found for [$identifier] version [$($target.Version)]. Files present: $([String]::Join(', ', @($files | ForEach-Object { $_.name })))"
    }

    # Locale manifest: prefer the declared default locale, then en-US, then whatever exists.
    $localeDocument = $null
    if ($isSingleton)
    {
        $localeDocument = $installerDocument
    }
    elseif (-not $SkipLocale -and $localeFiles.Count -gt 0)
    {
        $defaultLocale = [String](Get-WingetYamlValue -Node $versionDocument -Name 'DefaultLocale')
        $selectedLocale = @()

        if (-not [String]::IsNullOrWhiteSpace($defaultLocale))
        {
            $selectedLocale = @($localeFiles | Where-Object { [String]$_.name -like "*.locale.$defaultLocale.yaml" })
        }
        if ($selectedLocale.Count -eq 0)
        {
            $selectedLocale = @($localeFiles | Where-Object { [String]$_.name -like '*.locale.en-US.yaml' })
        }
        if ($selectedLocale.Count -eq 0)
        {
            $selectedLocale = @($localeFiles)
        }

        $localeDocument = Get-WingetManifestDocument -FileEntry $selectedLocale[0]
    }

    $rawInstallers = @(Get-WingetYamlValue -Node $installerDocument -Name 'Installers')
    if ($rawInstallers.Count -eq 0)
    {
        throw "Manifest for [$identifier] version [$($target.Version)] declares no installers."
    }

    $installers = @($rawInstallers | ForEach-Object { ConvertTo-WingetInstallerObject -Installer $_ -Root $installerDocument })

    $missingHash = @($installers | Where-Object { [String]::IsNullOrWhiteSpace($_.InstallerSha256) })
    if ($missingHash.Count -gt 0)
    {
        Write-Warning "$($missingHash.Count) installer entry/entries for [$identifier] $($target.Version) have no InstallerSha256; integrity cannot be verified for those."
    }

    $manifestVersion = [String](Get-WingetYamlValue -Node $installerDocument -Name 'ManifestVersion')
    $resolvedVersion = [String](Get-WingetYamlValue -Node $installerDocument -Name 'PackageVersion')
    if ([String]::IsNullOrWhiteSpace($resolvedVersion))
    {
        $resolvedVersion = $target.Version
    }

    return [PSCustomObject]@{
        PackageIdentifier = [String](Get-WingetYamlValue -Node $installerDocument -Name 'PackageIdentifier')
        PackageVersion = $resolvedVersion
        PackageName = [String](Get-WingetYamlValue -Node $localeDocument -Name 'PackageName')
        Publisher = [String](Get-WingetYamlValue -Node $localeDocument -Name 'Publisher')
        Moniker = [String](Get-WingetYamlValue -Node $localeDocument -Name 'Moniker')
        License = [String](Get-WingetYamlValue -Node $localeDocument -Name 'License')
        ShortDescription = [String](Get-WingetYamlValue -Node $localeDocument -Name 'ShortDescription')
        PackageUrl = [String](Get-WingetYamlValue -Node $localeDocument -Name 'PackageUrl')
        ReleaseDate = [String](Get-WingetYamlValue -Node $installerDocument -Name 'ReleaseDate')
        IsLatest = ($target.Version -eq @($availableVersions)[0].Version)
        IsPrerelease = [bool]$target.IsPrerelease
        ManifestVersion = $manifestVersion
        IsSingletonManifest = $isSingleton
        ManifestDirectory = "$manifestPath/$($target.Version)"
        ManifestSourceUris = @($sourceUris)
        RetrievedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        AvailableVersions = @($availableVersions | ForEach-Object { $_.Version })
        Installers = $installers
    }
}

function Select-WingetInstaller
{
    <#
    .SYNOPSIS
    Filters and ranks the installer entries of a manifest object.

    .DESCRIPTION
    Architecture, Scope, InstallerType and UrlLike act as filters. Results are ranked so that a
    direct installer is preferred over an archive that has to be unpacked first, and an entry
    whose scope is explicitly stated is preferred over one that inherits nothing.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Object]$Manifest,

        [Parameter(Mandatory = $false)]
        [String]$Architecture = '',

        [Parameter(Mandatory = $false)]
        [String]$Scope = '',

        [Parameter(Mandatory = $false)]
        [String]$InstallerType = '',

        [Parameter(Mandatory = $false)]
        [String]$UrlLike = '',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$PreferNested,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$First
    )

    process
    {
        $candidates = @($Manifest.Installers)

        if (-not [String]::IsNullOrWhiteSpace($Architecture))
        {
            $candidates = @($candidates | Where-Object { $_.Architecture -eq $Architecture })
        }
        if (-not [String]::IsNullOrWhiteSpace($Scope))
        {
            # An entry with no scope is a candidate for either scope, so it is not filtered out.
            $candidates = @($candidates | Where-Object { ($_.Scope -eq $Scope) -or [String]::IsNullOrWhiteSpace($_.Scope) })
        }
        if (-not [String]::IsNullOrWhiteSpace($InstallerType))
        {
            $candidates = @($candidates | Where-Object { ($_.EffectiveInstallerType -eq $InstallerType) -or ($_.InstallerType -eq $InstallerType) })
        }
        if (-not [String]::IsNullOrWhiteSpace($UrlLike))
        {
            $candidates = @($candidates | Where-Object { $_.InstallerUrl -like $UrlLike })
        }

        if ($candidates.Count -eq 0)
        {
            return
        }

        $ranked = @(
            $candidates | ForEach-Object {
                $nestedRank = if ($_.IsNested) { 0 } else { 1 }
                if ($PreferNested)
                {
                    $nestedRank = 1 - $nestedRank
                }

                $scopeRank = 0
                if (-not [String]::IsNullOrWhiteSpace($Scope) -and ($_.Scope -eq $Scope))
                {
                    $scopeRank = 1
                }

                [PSCustomObject]@{
                    Installer = $_
                    NestedRank = $nestedRank
                    ScopeRank = $scopeRank
                    HasHash = if ([String]::IsNullOrWhiteSpace($_.InstallerSha256)) { 0 } else { 1 }
                }
            } | Sort-Object -Property HasHash, ScopeRank, NestedRank -Descending
        )

        $result = @($ranked | ForEach-Object { $_.Installer })
        if ($First)
        {
            return @($result)[0]
        }
        return $result
    }
}

##================================================
## MARK: Entry point
##================================================

if ($MyInvocation.InvocationName -ne '.')
{
    $ErrorActionPreference = 'Stop'

    if ([String]::IsNullOrWhiteSpace($GitHubToken) -and -not [String]::IsNullOrWhiteSpace($env:GITHUB_TOKEN))
    {
        $GitHubToken = $env:GITHUB_TOKEN
    }

    if ([String]::IsNullOrWhiteSpace($PackageIdentifier) -and [String]::IsNullOrWhiteSpace($Moniker))
    {
        throw 'Supply -PackageIdentifier or -Moniker. Example: .\WingetManifestMetadata.ps1 -PackageIdentifier TeamViewer.TeamViewer.Host'
    }

    $resolvedIdentifier = $PackageIdentifier
    if (-not [String]::IsNullOrWhiteSpace($Moniker))
    {
        $resolvedIdentifier = Resolve-WingetPackageIdentifier -Moniker $Moniker
        Write-Verbose "Moniker [$Moniker] resolved to [$resolvedIdentifier]."
    }

    if ($ListVersions)
    {
        $result = @(Get-WingetPackageVersion -PackageIdentifier $resolvedIdentifier -Branch $Branch -GitHubToken $GitHubToken |
                Select-Object -Property Version, IsPrerelease, Path)
    }
    else
    {
        $result = Get-WingetPackageManifest `
            -PackageIdentifier $resolvedIdentifier `
            -Version $Version `
            -Branch $Branch `
            -GitHubToken $GitHubToken `
            -IncludePrerelease:$IncludePrerelease `
            -SkipLocale:$SkipLocale

        $filterUsed = -not ([String]::IsNullOrWhiteSpace($Architecture) -and
            [String]::IsNullOrWhiteSpace($Scope) -and
            [String]::IsNullOrWhiteSpace($InstallerType) -and
            [String]::IsNullOrWhiteSpace($UrlLike))

        if ($filterUsed)
        {
            $filtered = @(Select-WingetInstaller -Manifest $result -Architecture $Architecture -Scope $Scope -InstallerType $InstallerType -UrlLike $UrlLike)
            if ($filtered.Count -eq 0)
            {
                $available = [String]::Join(', ', @($result.Installers | ForEach-Object { "$($_.Architecture)/$($_.EffectiveInstallerType)" }))
                throw "No installer matched the requested filters. Available entries: $available"
            }
            $result.Installers = $filtered
        }
    }

    $json = $null
    if ($AsJson -or -not [String]::IsNullOrWhiteSpace($OutFile))
    {
        $json = ($result | ConvertTo-Json -Depth 12)
    }

    if (-not [String]::IsNullOrWhiteSpace($OutFile))
    {
        $outDirectory = Split-Path -Path $OutFile -Parent
        if (-not [String]::IsNullOrWhiteSpace($outDirectory) -and -not (Test-Path -LiteralPath $outDirectory))
        {
            New-Item -Path $outDirectory -ItemType Directory -Force | Out-Null
        }
        # UTF-8 without BOM so the file is safe for other tooling to read.
        [System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding($false)))
        Write-Verbose "Wrote [$OutFile]."
    }

    if ($AsJson)
    {
        $json
    }
    else
    {
        $result
    }
}
