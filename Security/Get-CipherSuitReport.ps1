$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$path = "C:\Temp\TLSCipherReport_$timestamp.xlsx"
$wsName = 'TLSCipherSuites'

$report = @()
ForEach($i in $(Get-TlsCipherSuite)) {

    $obj= [pscustomobject]@{
        Name = $i.Name
        Certificate = $i.Certificate
        Cipher = $i.Cipher
        CipherSuite = $i.CipherSuite
        CipherLength = $i.CipherLength
        CipherBlockLength = $i.CipherBlockLength
        BaseCipherSuite = $i.BaseCipherSuite
        Exchange = $i.Exchange
        Hash = $i.Hash
        HashLength = $i.HashLength
        KeyLength = $i.KeyLength
        KeyType = $i.KeyType
        Protocols = $(
            @($i.Protocols) |
            ForEach-Object {
                switch ([uint32]$_) {
                    768   { "TLS 1.0" }
                    769   { "TLS 1.1" }
                    770   { "TLS 1.2" }
                    771   { "TLS 1.3" }
                    772   { "TLS 1.3 (alt)" }
                    65277 { "DTLS 1.0" }
                    65279 { "DTLS 1.2" }
                    default { "Unknown ($_)" }
                }
            } |
            Sort-Object -Unique
        ) -join ", "
    }
    $report += $obj
}

# Export everything (most reliable). You can later narrow columns if you want.
$report | Export-Excel -Path $path -AutoSize -FreezeTopRow -BoldTopRow -TableName "TLSCipherSuites" -WorksheetName $wsName -TableStyle Medium6

Write-Host "Report created:`n$path" -ForegroundColor Cyan
