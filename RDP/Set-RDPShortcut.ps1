$rdpPath = "C:\Temp\MyServerConnection.rdp" # Change to your desired path
$server = "your.remote.server.com" # Change to your server address
$username = "DOMAIN\user"  # Change to your domain and username

$rdpContent = @"
full address:s:$server                  # Server name or IP
username:s:$username                    # Pre-fill username (leave blank to always prompt)
prompt for credentials:i:1              # 1 = Always prompt, 0 = use stored credentials
administrative session:i:1              # 1 = Connect to admin session (like /admin)

desktopwidth:i:1920                     # Width of the RDP window
desktopheight:i:1080                    # Height of the RDP window
screen mode id:i:2                      # 1 = Windowed, 2 = Full screen
smart sizing:i:1                        # Scale the desktop to fit window
use multimon:i:1                        # Use multiple monitors if available

audiomode:i:0                           # 0 = play locally, 1 = play remotely, 2 = mute
audiocapturemode:i:1                    # 1 = enable microphone redirection
redirectprinters:i:0                    # 0 = don't redirect printers
redirectclipboard:i:1                   # 1 = enable clipboard sharing
redirectdrives:i:1                      # 1 = enable drive sharing
redirectcomports:i:0
redirectsmartcards:i:1

enablecredsspsupport:i:1                # Use CredSSP for authentication
authentication level:i:2                # 0 = No auth, 1 = Optional, 2 = Require

connection type:i:6                     # 1=Modem, 2=LowSpeedBroadband, 6=LAN
disable wallpaper:i:1
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:0
"@

# Remove comments (everything after a '#') and trim whitespace
$cleanContent = $rdpContent -split "`n" | ForEach-Object {
    ($_ -replace '\s+#.*$','').Trim()
} | Where-Object {$_ -ne ""}

# Save cleaned content
$cleanContent | Set-Content -Path $rdpPath -Encoding ASCII
