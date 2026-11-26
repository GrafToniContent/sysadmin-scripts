<#
.SYNOPSIS
    Who became admin in your Entra ID tenant in the last X days?

.DESCRIPTION
    Attackers who take over an account often give themselves (or a new account)
    a privileged role. This script reads the Entra ID audit log and lists every
    role assignment and removal, including who did it and from where.

    Highlights Global Administrator and other highly privileged roles.
    Read-only. Permission: AuditLog.Read.All
    Note: the audit log keeps 30 days (Entra ID P1/P2) or 7 days (free).

.EXAMPLE
    .\23-Get-EntraRoleAssignmentChanges.ps1 -Days 30
#>
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Reports
[CmdletBinding()]
param(
    [ValidateRange(1, 30)][int]$Days = 30,
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
Connect-MgGraph -Scopes 'AuditLog.Read.All' -NoWelcome

$critical = 'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
            'Security Administrator', 'Exchange Administrator', 'Application Administrator',
            'Cloud Application Administrator', 'User Administrator', 'Conditional Access Administrator'

$since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
# startswith also catches the PIM variants, e.g. 'Add member to role completed (PIM activation)'
$filter = "activityDateTime ge $since and (startswith(activityDisplayName,'Add member to role') or " +
          "startswith(activityDisplayName,'Remove member from role') or " +
          "startswith(activityDisplayName,'Add eligible member to role') or " +
          "startswith(activityDisplayName,'Remove eligible member from role'))"

$events = Get-MgAuditLogDirectoryAudit -All -Filter $filter

$rows = foreach ($e in $events) {
    $target = $e.TargetResources | Where-Object Type -eq 'User' | Select-Object -First 1
    if (-not $target) { $target = $e.TargetResources | Select-Object -First 1 }
    $roleProp = $e.TargetResources.ModifiedProperties | Where-Object DisplayName -eq 'Role.DisplayName' | Select-Object -First 1
    $role = if ($roleProp) { ($roleProp.NewValue, $roleProp.OldValue | Where-Object { $_ -and $_ -ne '""' } | Select-Object -First 1) -replace '"', '' } else { '?' }
    $actor = if ($e.InitiatedBy.User.UserPrincipalName) { $e.InitiatedBy.User.UserPrincipalName } else { $e.InitiatedBy.App.DisplayName }

    [pscustomobject]@{
        Time     = $e.ActivityDateTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm')
        Action   = $e.ActivityDisplayName -replace ' member', ''
        Role     = $role
        Target   = if ($target.UserPrincipalName) { $target.UserPrincipalName } else { $target.DisplayName }
        By       = $actor
        FromIP   = $e.InitiatedBy.User.IpAddress
        Critical = $role -in $critical
        Result   = $e.Result
    }
}

if (-not $rows) {
    Write-Host "No role changes in the last $Days days." -ForegroundColor Green
} else {
    foreach ($r in $rows | Sort-Object Time -Descending) {
        $color = if ($r.Critical -and $r.Action -like 'Add*') { 'Red' } elseif ($r.Action -like 'Add*') { 'Yellow' } else { 'Gray' }
        Write-Host ("{0}  {1,-22} {2,-32} {3}  (by {4} {5})" -f $r.Time, $r.Action, $r.Role, $r.Target, $r.By, $r.FromIP) -ForegroundColor $color
    }
    $crit = @($rows | Where-Object { $_.Critical -and $_.Action -like 'Add*' }).Count
    Write-Host "`n$(@($rows).Count) role changes, $crit critical additions." -ForegroundColor Cyan
    if ($crit) { Write-Host 'Verify every critical addition with the person who made it - out of band, not by email.' -ForegroundColor Yellow }
    if ($CsvPath) { $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 }
}
Disconnect-MgGraph | Out-Null
