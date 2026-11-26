<#
.SYNOPSIS
    Who still authenticates with NTLM - and NTLMv1 - in your domain?

.DESCRIPTION
    Microsoft is phasing out NTLM; Windows Server 2025 removed NTLMv1 and can block
    NTLM entirely. Before you turn it off, you need to know who still uses it.

    Reads successful logon events (4624) from the Security log of your domain
    controllers (or any server) and groups NTLM logons by account, source workstation
    and IP. NTLMv1 is flagged red.
    Read-only. Run as Domain Admin / Event Log Reader. Large logs: limit -Hours.

.EXAMPLE
    .\17-Find-NtlmUsage.ps1                          # all DCs, last 24 h
.EXAMPLE
    .\17-Find-NtlmUsage.ps1 -ComputerName FS01 -Hours 72 -CsvPath C:\Temp\ntlm.csv
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [int]$Hours = 24,
    [int]$MaxEvents = 50000,
    [string]$CsvPath
)

if (-not $ComputerName) {
    Import-Module ActiveDirectory -ErrorAction Stop
    $ComputerName = (Get-ADDomainController -Filter *).HostName
}

$xpath = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $($Hours * 3600000)]]] and " +
         "*[EventData[Data[@Name='AuthenticationPackageName']='NTLM']]"

$events = foreach ($dc in $ComputerName) {
    Write-Host "Reading $dc ..." -ForegroundColor DarkGray
    try {
        $raw = @(Get-WinEvent -ComputerName $dc -LogName Security -FilterXPath $xpath -MaxEvents $MaxEvents -ErrorAction Stop)
        if ($raw.Count -ge $MaxEvents) { Write-Warning "$dc : -MaxEvents $MaxEvents reached - results are incomplete. Use a smaller -Hours or a higher -MaxEvents." }
        $raw | ForEach-Object {
            $x = [xml]$_.ToXml()
            $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            [pscustomobject]@{
                Server      = $dc
                Account     = "$($d.TargetDomainName)\$($d.TargetUserName)"
                Workstation = $d.WorkstationName
                SourceIP    = $d.IpAddress
                Version     = $d.LmPackageName
                LogonType   = $d.LogonType
            }
        }
    } catch {
        # 'No events found' is not an error - check the error ID, the message text is localized
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { Write-Warning "$dc : $($_.Exception.Message)" }
    }
}

# Ignore anonymous logons (null sessions) - they show up as NTLM too
$events = $events | Where-Object { $_.Account -notmatch 'ANONYMOUS LOGON' }

if (-not $events) { Write-Host "No NTLM logons in the last $Hours h. Nice." -ForegroundColor Green; return }

$grouped = $events | Group-Object Account, Workstation, SourceIP, Version | ForEach-Object {
    $f = $_.Group[0]
    [pscustomobject]@{ Count = $_.Count; Account = $f.Account; Workstation = $f.Workstation; SourceIP = $f.SourceIP; Version = $f.Version }
} | Sort-Object Count -Descending

foreach ($g in $grouped | Select-Object -First 40) {
    $color = if ($g.Version -like '*V1*') { 'Red' } else { 'Yellow' }
    Write-Host ("{0,6}x  {1,-35} {2,-18} {3,-16} {4}" -f $g.Count, $g.Account, $g.Workstation, $g.SourceIP, $g.Version) -ForegroundColor $color
}
$v1 = @($events | Where-Object Version -like '*V1*').Count
Write-Host ("`n{0} NTLM logons ({1} NTLMv1) from {2} sources in the last {3} h." -f @($events).Count, $v1, @($grouped).Count, $Hours) -ForegroundColor Cyan
if ($CsvPath) { $grouped | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 }
Write-Host 'Next: fix NTLMv1 sources first, use DNS names instead of IPs (IP = NTLM), check SPNs, then audit -> restrict NTLM via GPO.' -ForegroundColor DarkGray
