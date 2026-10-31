<#
.SYNOPSIS
    Finds and disables enabled AD users without a logon for X days.

.DESCRIPTION
    Finds enabled accounts whose LastLogonDate is older than -Days (or that never logged on),
    skips accounts created within that period, writes a CSV report and disables the accounts.
    Asks for confirmation per account (ConfirmImpact High). Use -WhatIf for a dry run and
    -Confirm:$false only once you have reviewed the report.

    Note: LastLogonDate (lastLogonTimestamp) replicates with a delay of up to ~14 days,
    so it is suited for cleanup with periods of 30+ days, not for exact logon times.

.EXAMPLE
    .\02-Disable-StaleADUsers.ps1 -Days 90 -WhatIf

.EXAMPLE
    .\02-Disable-StaleADUsers.ps1 -Days 90 -SearchBase 'OU=Users,OU=Company,DC=lab,DC=local' `
        -ExcludeSamAccountName 'svc-backup','svc-sql'

.NOTES
    Graf Toni Content - "Automate it once. Never do it again."
    Review the report before disabling: service accounts often never log on interactively.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateRange(1, 3650)][int]$Days = 90,
    [string]$SearchBase,
    [string]$ReportPath = ".\stale-users-$(Get-Date -Format yyyy-MM-dd).csv",
    [string[]]$ExcludeSamAccountName = @()
)

Import-Module ActiveDirectory -ErrorAction Stop

$cutoff    = (Get-Date).AddDays(-$Days)
$getParams = @{ Filter = 'Enabled -eq $true'; Properties = 'LastLogonDate', 'whenCreated' }
if ($SearchBase) { $getParams.SearchBase = $SearchBase }

$stale = @(Get-ADUser @getParams | Where-Object {
    ($null -eq $_.LastLogonDate -or $_.LastLogonDate -lt $cutoff) -and
    $_.whenCreated -lt $cutoff -and
    $ExcludeSamAccountName -notcontains $_.SamAccountName
})

$stale | Select-Object Name, SamAccountName, LastLogonDate, whenCreated, DistinguishedName |
    Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8

Write-Host "$($stale.Count) stale account(s) found. Report: $ReportPath" -ForegroundColor Cyan

foreach ($u in $stale) {
    if ($PSCmdlet.ShouldProcess($u.SamAccountName, 'Disable AD account')) {
        try {
            Disable-ADAccount -Identity $u -ErrorAction Stop
            Write-Host "Disabled $($u.SamAccountName)" -ForegroundColor Yellow
        }
        catch {
            Write-Warning "Could not disable $($u.SamAccountName): $($_.Exception.Message)"
        }
    }
}
