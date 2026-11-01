<#
.SYNOPSIS
    Restarts stopped Windows services and optionally emails the team.

.DESCRIPTION
    Checks one or more services. If a service is not running (and not disabled on purpose),
    it is started, the result is verified after -WaitSeconds and - if SMTP details are
    given - an email is sent so nothing goes unnoticed.

.EXAMPLE
    .\05-Restart-ServiceSelfHeal.ps1 -Name Spooler

.EXAMPLE
    .\05-Restart-ServiceSelfHeal.ps1 -Name Spooler, W3SVC -SmtpServer mail.lab.local `
        -From monitor@lab.local -To it@lab.local

.EXAMPLE
    # Every 5 minutes via Task Scheduler
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -File C:\Scripts\05-Restart-ServiceSelfHeal.ps1 -Name Spooler'
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName 'SelfHeal-Spooler' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest

.NOTES
    Graf Toni Content - "Automate it once. Never do it again."
    A service that keeps crashing needs a root-cause fix - self-healing only buys you time.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Name,
    [string]$SmtpServer,
    [string]$From,
    [string[]]$To,
    [ValidateRange(1, 300)][int]$WaitSeconds = 10
)

foreach ($n in $Name) {
    $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Warning "Service '$n' not found"; continue }
    if ($svc.StartType -eq 'Disabled') { Write-Verbose "'$n' is disabled - skipped"; continue }
    if ($svc.Status -eq 'Running') { Write-Verbose "'$n' is running"; continue }

    $before = $svc.Status
    try   { Start-Service -Name $n -ErrorAction Stop }
    catch { Write-Warning "Starting '$n' failed: $($_.Exception.Message)" }

    Start-Sleep -Seconds $WaitSeconds
    $after = (Get-Service -Name $n).Status
    $msg   = "Service '$n' on $env:COMPUTERNAME was $before. Restart attempted. Current status: $after."
    Write-Host $msg -ForegroundColor $(if ($after -eq 'Running') { 'Green' } else { 'Red' })

    if ($SmtpServer -and $From -and $To) {
        Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To `
            -Subject "[$after] $n restarted on $env:COMPUTERNAME" -Body $msg -Encoding UTF8
    }
}
