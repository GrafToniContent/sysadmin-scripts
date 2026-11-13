<#
.SYNOPSIS
    Finds expiring or expired client secrets and certificates of Entra ID app registrations.

.DESCRIPTION
    Expired app secrets are one of the most common causes of "M365 integration suddenly
    stopped working" (backup, scanner-to-mail, monitoring, CRM sync ...).
    Also flags secrets with an extremely long lifetime (> 2 years = security risk).

    Exit codes for monitoring (ServerEye, PRTG ...):
      0 = OK, 1 = something expires within -WarningDays, 2 = something expires within -CriticalDays
      (already expired credentials are listed but don't raise the exit code - usually old, unused apps)

.EXAMPLE
    .\14-Get-EntraAppCredentialExpiry.ps1 -WarningDays 30 -CriticalDays 7
.EXAMPLE
    .\14-Get-EntraAppCredentialExpiry.ps1 -CsvPath C:\Temp\appsecrets.csv -IncludeOk

.NOTES
    Permission: Application.Read.All. Module: Microsoft.Graph.Applications
#>
[CmdletBinding()]
param(
    [int]$WarningDays = 30,
    [int]$CriticalDays = 7,
    [switch]$IncludeOk,
    [string]$CsvPath,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint
)

$ErrorActionPreference = 'Stop'
if ($ClientId -and $CertificateThumbprint -and $TenantId) {
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
} else {
    Connect-MgGraph -Scopes 'Application.Read.All' -NoWelcome
}

$now = Get-Date
$apps = Get-MgApplication -All -Property Id, AppId, DisplayName, PasswordCredentials, KeyCredentials

$rows = foreach ($app in $apps) {
    $creds = @($app.PasswordCredentials | ForEach-Object { $_ | Add-Member -NotePropertyName Kind -NotePropertyValue 'Secret' -PassThru -Force }) +
             @($app.KeyCredentials | ForEach-Object { $_ | Add-Member -NotePropertyName Kind -NotePropertyValue 'Certificate' -PassThru -Force })

    foreach ($c in $creds | Where-Object { $_ -and $_.EndDateTime }) {
        $end = $c.EndDateTime.ToLocalTime()
        $days = [math]::Floor(($end - $now).TotalDays)
        $lifetime = if ($c.StartDateTime) { [math]::Round(($c.EndDateTime - $c.StartDateTime).TotalDays) } else { $null }

        $status = if ($days -lt 0) { 'EXPIRED' }
                  elseif ($days -le $CriticalDays) { 'CRITICAL' }
                  elseif ($days -le $WarningDays) { 'WARNING' }
                  else { 'OK' }
        $note = if ($c.Kind -eq 'Secret' -and $lifetime -gt 730) { "Long-lived secret ($lifetime days)" } else { '' }

        [pscustomobject]@{
            Status = $status; App = $app.DisplayName; AppId = $app.AppId; Type = $c.Kind
            Name = $c.DisplayName; Expires = $end.ToString('yyyy-MM-dd'); DaysLeft = $days; Note = $note
        }
    }
}

$order = @{ EXPIRED = 0; CRITICAL = 1; WARNING = 2; OK = 3 }
$view = $rows | Where-Object { $IncludeOk -or $_.Status -ne 'OK' -or $_.Note } | Sort-Object @{ e = { $order[$_.Status] } }, DaysLeft

if ($view) { $view | Format-Table Status, App, Type, Name, Expires, DaysLeft, Note -AutoSize }
else { Write-Host "No credentials expiring within $WarningDays days." -ForegroundColor Green }

if ($CsvPath) { $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 }

# Note: expired credentials of apps that are no longer used are noise - delete them in Entra ID.
$exit = if ($rows | Where-Object Status -in 'CRITICAL') { 2 }
        elseif ($rows | Where-Object Status -eq 'WARNING') { 1 }
        else { 0 }
$expired = @($rows | Where-Object Status -eq 'EXPIRED').Count
Write-Host "`n$(@($apps).Count) apps checked. Expired: $expired | Critical: $(@($rows | Where-Object Status -eq 'CRITICAL').Count) | Warning: $(@($rows | Where-Object Status -eq 'WARNING').Count)" -ForegroundColor Cyan
Disconnect-MgGraph | Out-Null
exit $exit
