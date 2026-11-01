<#
.SYNOPSIS
    Emails an alert when a server disk drops below X % free space.

.DESCRIPTION
    Checks all local disks (DriveType 3) on the servers listed in a text file, collects
    every disk below -ThresholdPercent free and sends ONE HTML email - only if there is
    something to report. Unreachable servers are reported too: a monitoring script that
    fails silently is worse than none.

    Send-MailMessage is marked obsolete by Microsoft but still works with an internal
    SMTP relay. For Microsoft 365-only environments use Graph (Send-MgUserMail) instead.

.EXAMPLE
    .\04-Send-DiskAlert.ps1 -ServerListPath .\servers.txt -ThresholdPercent 15 `
        -SmtpServer mail.lab.local -From monitor@lab.local -To it@lab.local

.EXAMPLE
    # Run every hour via Task Scheduler (use a service account with read rights on the servers)
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -File C:\Scripts\04-Send-DiskAlert.ps1 -SmtpServer mail.lab.local -From monitor@lab.local -To it@lab.local'
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName 'DiskAlert' -Action $action -Trigger $trigger -User 'LAB\svc-monitor' -Password '<password>'

.NOTES
    Graf Toni Content - "Automate it once. Never do it again."
#>
[CmdletBinding()]
param(
    [string]$ServerListPath = '.\servers.txt',
    [ValidateRange(1, 99)][int]$ThresholdPercent = 15,
    [Parameter(Mandatory)][string]$SmtpServer,
    [Parameter(Mandatory)][string]$From,
    [Parameter(Mandatory)][string[]]$To
)

$servers = Get-Content -Path $ServerListPath | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() }

$alerts = foreach ($s in $servers) {
    try {
        Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $s -Filter 'DriveType=3' -ErrorAction Stop |
            Where-Object { $_.Size -gt 0 -and ($_.FreeSpace / $_.Size * 100) -lt $ThresholdPercent } |
            Select-Object @{ n = 'Server';  e = { $s } }, DeviceID,
                          @{ n = 'FreeGB';  e = { [math]::Round($_.FreeSpace / 1GB, 1) } },
                          @{ n = 'FreePct'; e = { [math]::Round($_.FreeSpace / $_.Size * 100, 1) } }
    }
    catch {
        [pscustomobject]@{ Server = $s; DeviceID = 'UNREACHABLE'; FreeGB = $null; FreePct = $null }
    }
}

if ($alerts) {
    $body = $alerts | ConvertTo-Html -Fragment -PreContent "<h3>Disks below $ThresholdPercent % free</h3>" | Out-String
    Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To `
        -Subject "Disk alert: $(@($alerts).Count) issue(s)" -Body $body -BodyAsHtml -Encoding UTF8
    Write-Host "Alert sent for $(@($alerts).Count) issue(s)." -ForegroundColor Yellow
}
else {
    Write-Host 'All disks OK.' -ForegroundColor Green
}
