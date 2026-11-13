<#
.SYNOPSIS
    Checks Microsoft 365 service health (Exchange, Teams, SharePoint, Entra ID ...) via Microsoft Graph.

.DESCRIPTION
    - Shows the health status of every M365 service in your tenant
    - Lists open incidents and advisories (with impact description)
    - Optional: recent Message Center posts (upcoming changes)
    - Optional: watch mode (polls every N minutes, only reports changes)
    - Optional: Teams notification via Workflows/Incoming Webhook URL
    - Exit codes for monitoring tools (ServerEye, PRTG, Nagios ...):
        0 = all services operational, 1 = advisory, 2 = incident / degradation

    Read-only. Needs only the permission ServiceHealth.Read.All
    (plus ServiceMessage.Read.All for -IncludeMessageCenter).

.PARAMETER Service
    Filter by service name (wildcards allowed), e.g. "Exchange*", "*Teams*".

.PARAMETER IncludeMessageCenter
    Also show Message Center posts of the last -MessageCenterDays days.

.PARAMETER Watch
    Keep running and poll every -IntervalMinutes. Only changes are printed / posted.

.PARAMETER TeamsWebhookUrl
    Optional Teams webhook (Workflows "Post to a channel when a webhook request is received").

.PARAMETER TenantId / ClientId / CertificateThumbprint
    For unattended runs (scheduled task, monitoring) with an app registration + certificate.
    Without these, an interactive login is used.

.EXAMPLE
    .\08-Get-M365ServiceHealth.ps1

.EXAMPLE
    .\08-Get-M365ServiceHealth.ps1 -Service "*Exchange*","*Teams*" -IncludeMessageCenter

.EXAMPLE
    .\08-Get-M365ServiceHealth.ps1 -Watch -IntervalMinutes 5 -TeamsWebhookUrl "https://..."

.NOTES
    Requires: Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Devices.ServiceAnnouncement
#>
[CmdletBinding()]
param(
    [string[]]$Service,
    [switch]$IncludeMessageCenter,
    [int]$MessageCenterDays = 7,
    [switch]$Watch,
    [int]$IntervalMinutes = 5,
    [string]$TeamsWebhookUrl,
    [string]$ExportCsv,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint
)

$ErrorActionPreference = 'Stop'

#region --- Connect --------------------------------------------------------------
foreach ($m in 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Devices.ServiceAnnouncement') {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        throw "Module '$m' missing. Install with: Install-Module $m -Scope CurrentUser"
    }
}

if ($ClientId -and $CertificateThumbprint -and $TenantId) {
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
} else {
    $scopes = @('ServiceHealth.Read.All')
    if ($IncludeMessageCenter) { $scopes += 'ServiceMessage.Read.All' }
    Connect-MgGraph -Scopes $scopes -NoWelcome
}
#endregion

#region --- Helpers --------------------------------------------------------------
function Get-StatusColor([string]$Status) {
    switch -Wildcard ($Status) {
        'serviceOperational'        { 'Green' }
        'serviceRestored'           { 'Green' }
        'postIncidentReviewPublished' { 'Green' }
        'falsePositive'             { 'Green' }
        'investigationSuspended'    { 'Yellow' }
        'investigating'             { 'Yellow' }
        'verifyingService'          { 'Yellow' }
        'restoringService'          { 'Yellow' }
        'mitigated*'                { 'Yellow' }
        'extendedRecovery'          { 'Yellow' }
        'serviceDegradation'        { 'Red' }
        'serviceInterruption'       { 'Red' }
        default                     { 'Gray' }
    }
}

function Test-ServiceFilter([string]$Name) {
    if (-not $Service) { return $true }
    foreach ($s in $Service) { if ($Name -like $s) { return $true } }
    return $false
}

function Send-TeamsMessage([string]$Text) {
    if (-not $TeamsWebhookUrl) { return }
    # Adaptive Card payload - works with Teams Workflows webhooks
    $card = @{
        type        = 'message'
        attachments = @(@{
            contentType = 'application/vnd.microsoft.card.adaptive'
            content     = @{
                '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                type      = 'AdaptiveCard'
                version   = '1.4'
                body      = @(
                    @{ type = 'TextBlock'; text = 'M365 Service Health'; weight = 'Bolder'; size = 'Medium' },
                    @{ type = 'TextBlock'; text = $Text; wrap = $true }
                )
            }
        })
    }
    try {
        Invoke-RestMethod -Uri $TeamsWebhookUrl -Method Post -ContentType 'application/json' `
            -Body ($card | ConvertTo-Json -Depth 10) | Out-Null
    } catch {
        Write-Warning "Teams notification failed: $($_.Exception.Message)"
    }
}

function Get-HealthSnapshot {
    $overview = Get-MgServiceAnnouncementHealthOverview -All |
        Where-Object { Test-ServiceFilter $_.Service } |
        Sort-Object Service

    $issues = Get-MgServiceAnnouncementIssue -All -Filter 'isResolved eq false' |
        Where-Object { Test-ServiceFilter $_.Service } |
        Sort-Object Classification, StartDateTime

    [pscustomobject]@{ Overview = $overview; Issues = $issues }
}

function Show-Snapshot($Snap) {
    Write-Host "`n=== Microsoft 365 Service Health - $(Get-Date -Format 'yyyy-MM-dd HH:mm') ===`n" -ForegroundColor Cyan

    foreach ($svc in $Snap.Overview) {
        $color = Get-StatusColor $svc.Status
        Write-Host ('{0,-45} {1}' -f $svc.Service, $svc.Status) -ForegroundColor $color
    }

    Write-Host "`n--- Open incidents & advisories: $(@($Snap.Issues).Count) ---`n" -ForegroundColor Cyan
    foreach ($i in $Snap.Issues) {
        $color = if ($i.Classification -eq 'incident') { 'Red' } else { 'Yellow' }
        Write-Host ("[{0}] {1} - {2}" -f $i.Id, $i.Classification.ToUpper(), $i.Service) -ForegroundColor $color
        Write-Host ("   {0}" -f $i.Title)
        Write-Host ("   Status: {0} | since {1:yyyy-MM-dd HH:mm} | updated {2:yyyy-MM-dd HH:mm}" -f `
            $i.Status, $i.StartDateTime.ToLocalTime(), $i.LastModifiedDateTime.ToLocalTime()) -ForegroundColor DarkGray
        if ($i.ImpactDescription) { Write-Host ("   Impact: {0}" -f $i.ImpactDescription) -ForegroundColor DarkGray }
    }
}

function Get-ExitCode($Snap) {
    if ($Snap.Issues | Where-Object Classification -eq 'incident') { return 2 }
    if ($Snap.Overview | Where-Object { $_.Status -in 'serviceDegradation', 'serviceInterruption' }) { return 2 }
    if ($Snap.Issues) { return 1 }
    return 0
}
#endregion

#region --- Single run -----------------------------------------------------------
if (-not $Watch) {
    $snap = Get-HealthSnapshot
    Show-Snapshot $snap

    if ($IncludeMessageCenter) {
        $since = (Get-Date).ToUniversalTime().AddDays(-$MessageCenterDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $msgs = Get-MgServiceAnnouncementMessage -All -Filter "lastModifiedDateTime ge $since" |
            Sort-Object LastModifiedDateTime -Descending
        Write-Host "`n--- Message Center (last $MessageCenterDays days): $(@($msgs).Count) ---`n" -ForegroundColor Cyan
        foreach ($m in $msgs) {
            $tag = if ($m.IsMajorChange) { ' [MAJOR]' } else { '' }
            Write-Host ("[{0}]{1} {2}" -f $m.Id, $tag, $m.Title)
            if ($m.ActionRequiredByDateTime) {
                Write-Host ("   Action required by {0:yyyy-MM-dd}" -f $m.ActionRequiredByDateTime) -ForegroundColor Yellow
            }
        }
    }

    if ($ExportCsv) {
        $snap.Issues | Select-Object Id, Service, Classification, Status, Title, Feature,
            StartDateTime, LastModifiedDateTime, ImpactDescription |
            Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host "`nExported to $ExportCsv" -ForegroundColor Green
    }

    $code = Get-ExitCode $snap
    if ($code -gt 0) {
        $txt = ($snap.Issues | ForEach-Object { "$($_.Classification.ToUpper()) $($_.Service): $($_.Title)" }) -join "`n"
        Send-TeamsMessage $txt
    }
    Disconnect-MgGraph | Out-Null
    exit $code
}
#endregion

#region --- Watch mode -----------------------------------------------------------
Write-Host "Watch mode: polling every $IntervalMinutes min. Ctrl+C to stop." -ForegroundColor Cyan
$known = @{}   # IssueId -> Status
$first = $true

try {
    while ($true) {
        try {
            $snap = Get-HealthSnapshot
            $changes = @()

            foreach ($i in $snap.Issues) {
                if (-not $known.ContainsKey($i.Id)) {
                    $changes += "NEW $($i.Classification.ToUpper()) [$($i.Id)] $($i.Service): $($i.Title) ($($i.Status))"
                } elseif ($known[$i.Id] -ne $i.Status) {
                    $changes += "UPDATE [$($i.Id)] $($i.Service): $($known[$i.Id]) -> $($i.Status)"
                }
            }
            $openIds = @($snap.Issues.Id)
            foreach ($id in @($known.Keys)) {
                if ($id -notin $openIds) { $changes += "RESOLVED [$id]"; $known.Remove($id) }
            }
            foreach ($i in $snap.Issues) { $known[$i.Id] = $i.Status }

            if ($first) {
                Show-Snapshot $snap
                $first = $false
            } elseif ($changes) {
                $stamp = Get-Date -Format 'HH:mm'
                $changes | ForEach-Object { Write-Host "[$stamp] $_" -ForegroundColor Yellow }
                Send-TeamsMessage ($changes -join "`n")
            } else {
                Write-Host "[$(Get-Date -Format 'HH:mm')] no changes" -ForegroundColor DarkGray
            }
        } catch {
            Write-Warning "Poll failed: $($_.Exception.Message)"
        }
        Start-Sleep -Seconds ($IntervalMinutes * 60)
    }
} finally {
    Disconnect-MgGraph | Out-Null
}
#endregion
