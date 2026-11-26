<#
.SYNOPSIS
    Which computers are NOT protected by Windows LAPS?

.DESCRIPTION
    Same local admin password on every PC = one stolen hash and the attacker owns
    them all (pass-the-hash). Windows LAPS (built into Windows 11 / Server 2019+
    since April 2023) rotates a unique password per device.

    This script checks all enabled computers in Active Directory:
      - Windows LAPS password present (msLAPS-PasswordExpirationTime)?
      - legacy Microsoft LAPS only (ms-Mcs-AdmPwdExpirationTime)?
      - password expired (rotation not working)?
    Read-only. Needs the RSAT ActiveDirectory module. For Entra-joined devices
    check Intune > Devices > Local admin password instead.

.EXAMPLE
    .\21-Get-WindowsLapsStatus.ps1
.EXAMPLE
    .\21-Get-WindowsLapsStatus.ps1 -SearchBase 'OU=Workstations,DC=contoso,DC=local' -CsvPath C:\Temp\laps.csv
#>
#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [string]$SearchBase,
    [int]$StaleLogonDays = 60,
    [string]$CsvPath
)

Import-Module ActiveDirectory -ErrorAction Stop
# Get-ADComputer fails if a requested attribute is not in the schema (e.g. legacy LAPS never installed)
$schemaNC = (Get-ADRootDSE).schemaNamingContext
$lapsAttr = 'msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime' | Where-Object {
    Get-ADObject -SearchBase $schemaNC -Filter "lDAPDisplayName -eq '$_'"
}
if (-not $lapsAttr) { Write-Warning 'Neither Windows LAPS nor legacy LAPS is in the AD schema - run Update-LapsADSchema.' }
$props = @('OperatingSystem', 'LastLogonDate') + @($lapsAttr)
$p = @{ Filter = "Enabled -eq 'True' -and OperatingSystem -like 'Windows*'"; Properties = $props }
if ($SearchBase) { $p.SearchBase = $SearchBase }

$now = Get-Date
$rows = foreach ($c in Get-ADComputer @p) {
    $new = $c.'msLAPS-PasswordExpirationTime'
    $old = $c.'ms-Mcs-AdmPwdExpirationTime'
    $exp = if ($new) { [datetime]::FromFileTime([long]$new) } elseif ($old) { [datetime]::FromFileTime([long]$old) } else { $null }

    $status = if (-not $new -and -not $old) { 'NO LAPS' }
              elseif (-not $new) { 'Legacy LAPS' }
              elseif ($exp -lt $now) { 'EXPIRED' }
              else { 'OK' }
    if ($c.LastLogonDate -and $c.LastLogonDate -lt $now.AddDays(-$StaleLogonDays)) { $status += ' (stale computer)' }

    [pscustomobject]@{
        Computer = $c.Name; OS = $c.OperatingSystem; Status = $status
        PasswordExpires = if ($exp) { $exp.ToString('yyyy-MM-dd') } else { '' }
        LastLogon = if ($c.LastLogonDate) { $c.LastLogonDate.ToString('yyyy-MM-dd') } else { '' }
    }
}

$rows | Group-Object Status | Sort-Object Name |
    Select-Object @{n = 'Status'; e = { $_.Name } }, Count | Format-Table -AutoSize
$rows | Where-Object Status -notlike 'OK*' | Sort-Object Status, Computer | Format-Table -AutoSize

if ($CsvPath) { $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 }
Write-Host 'Fix: Update-LapsADSchema, Set-LapsADComputerSelfPermission -Identity <OU>, then enable the Windows LAPS policy (GPO or Intune). Migrate legacy LAPS clients.' -ForegroundColor DarkGray
