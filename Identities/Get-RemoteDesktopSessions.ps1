function Get-RemoteDesktopSessions {
    [CmdletBinding()]
    param ()

    # Retrieve remote desktop logon sessions (LogonType=10)
    $sessions = Get-WmiObject -Class Win32_LogonSession -Filter "LogonType=10"

    # Extract associated user information for each session
    $users = foreach ($session in $sessions) {
        $associations = Get-WmiObject -Query "ASSOCIATORS OF {Win32_LogonSession.LogonId=$($session.LogonId)} WHERE AssocClass=Win32_LoggedOnUser"
        foreach ($association in $associations) {
            [PSCustomObject]@{
                UserName   = $association.Name
                Domain     = $association.Domain
                LogonTime  = $session.ConvertToDateTime($session.StartTime)
            }
        }
    }

    # Return user details
    return $users
}
