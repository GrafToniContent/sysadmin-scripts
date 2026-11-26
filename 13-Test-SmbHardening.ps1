<#
.SYNOPSIS
    Checks SMB security on Windows Server 2025 (and older) - SMBv1, signing, encryption, NTLM.

.DESCRIPTION
    Windows Server 2025 requires SMB signing by default and can block NTLM for SMB.
    Older servers - and upgraded ones - often don't. This read-only script checks
    one or many servers via PowerShell Remoting:
      - SMBv1 server protocol disabled
      - SMB signing required (server + client)
      - SMB encryption (EncryptData / RejectUnencryptedAccess)
      - Guest / insecure guest logons blocked
      - Server 2025: NTLM blocked for SMB client (BlockNTLM), auth rate limiter
    Output: one PASS/WARN/FAIL line per check and server.

.EXAMPLE
    .\13-Test-SmbHardening.ps1
.EXAMPLE
    .\13-Test-SmbHardening.ps1 -ComputerName FS01,FS02,DC01 -CsvPath C:\Temp\smb.csv
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName = $env:COMPUTERNAME,
    [string]$CsvPath
)

$collect = {
    $s = Get-SmbServerConfiguration
    $c = Get-SmbClientConfiguration
    [pscustomobject]@{
        OS                       = (Get-CimInstance Win32_OperatingSystem).Caption
        SMB1                     = $s.EnableSMB1Protocol
        ServerSigningRequired    = $s.RequireSecuritySignature
        ClientSigningRequired    = $c.RequireSecuritySignature
        EncryptData              = $s.EncryptData
        RejectUnencrypted        = $s.RejectUnencryptedAccess
        InsecureGuestLogons      = $c.EnableInsecureGuestLogons
        BlockNTLM                = if ($c.PSObject.Properties.Name -contains 'BlockNTLM') { $c.BlockNTLM } else { 'n/a' }
        AuthRateLimiterMs        = if ($s.PSObject.Properties.Name -contains 'InvalidAuthenticationDelayTimeInMs') { $s.InvalidAuthenticationDelayTimeInMs } else { 'n/a' }
    }
}

$results = foreach ($pc in $ComputerName) {
    try {
        $r = if ($pc -eq $env:COMPUTERNAME) { & $collect } else { Invoke-Command -ComputerName $pc -ScriptBlock $collect -ErrorAction Stop }
    } catch { Write-Warning "$pc : $($_.Exception.Message)"; continue }

    $checks = @(
        ,@('SMBv1 disabled',               (-not $r.SMB1),                 'FAIL', 'Set-SmbServerConfiguration -EnableSMB1Protocol $false')
        ,@('Server signing required',      [bool]$r.ServerSigningRequired, 'FAIL', 'Set-SmbServerConfiguration -RequireSecuritySignature $true')
        ,@('Client signing required',      [bool]$r.ClientSigningRequired, 'WARN', 'Set-SmbClientConfiguration -RequireSecuritySignature $true')
        ,@('Insecure guest logons off',    (-not $r.InsecureGuestLogons),  'FAIL', 'Set-SmbClientConfiguration -EnableInsecureGuestLogons $false')
        ,@('Encryption (shares/server)',   [bool]$r.EncryptData,           'WARN', 'Set-SmbServerConfiguration -EncryptData $true (test clients first)')
        ,@('Unencrypted access rejected',  ((-not $r.EncryptData) -or [bool]$r.RejectUnencrypted), 'WARN', 'Set-SmbServerConfiguration -RejectUnencryptedAccess $true')
        ,@('NTLM blocked for SMB client',  ($r.BlockNTLM -eq $true),       'WARN', 'Server 2025: Set-SmbClientConfiguration -BlockNTLM $true (after NTLM audit)')
        ,@('Auth rate limiter on',         (($r.AuthRateLimiterMs -eq 'n/a') -or ([int]$r.AuthRateLimiterMs -gt 0)), 'WARN', 'Server 2025: Set-SmbServerConfiguration -InvalidAuthenticationDelayTimeInMs 2000')
    )
    Write-Host "`n=== $pc ($($r.OS)) ===" -ForegroundColor Cyan
    foreach ($c in $checks) {
        $status = if ($c[1]) { 'PASS' } else { $c[2] }
        $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red' }[$status]
        Write-Host ("[{0}] {1}" -f $status, $c[0]) -ForegroundColor $color
        if ($status -ne 'PASS') { Write-Host "       -> $($c[3])" -ForegroundColor DarkGray }
        [pscustomobject]@{ Computer = $pc; Check = $c[0]; Status = $status; Fix = if ($status -ne 'PASS') { $c[3] } else { '' } }
    }
}

if ($CsvPath) { $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 }
Write-Host "`nNote: signing/encryption changes can break old NAS, printers and scanners - test first." -ForegroundColor DarkGray
