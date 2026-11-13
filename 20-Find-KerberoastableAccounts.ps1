<#
.SYNOPSIS
    Finds service accounts that are easy targets for Kerberoasting.

.DESCRIPTION
    Any domain user can request a Kerberos service ticket for an account with an
    SPN and try to crack its password offline. Weak, old passwords on such accounts
    - especially privileged ones - are one of the most common paths to Domain Admin.

    This read-only script lists all enabled USER accounts with a ServicePrincipalName
    and flags:
      - privileged accounts (adminCount = 1)
      - password older than -MaxPasswordAgeDays
      - password never expires
      - RC4 still allowed (no AES-only msDS-SupportedEncryptionTypes)
    Recommendation: replace with (group) Managed Service Accounts - gMSA / dMSA on Server 2025.

.EXAMPLE
    .\20-Find-KerberoastableAccounts.ps1
#>
[CmdletBinding()]
param(
    [int]$MaxPasswordAgeDays = 365,
    [string]$CsvPath
)

Import-Module ActiveDirectory -ErrorAction Stop
$props = 'ServicePrincipalName', 'PasswordLastSet', 'PasswordNeverExpires', 'AdminCount', 'msDS-SupportedEncryptionTypes', 'LastLogonDate', 'Description'
$accounts = Get-ADUser -Filter "Enabled -eq 'True' -and ServicePrincipalName -like '*'" -Properties $props |
    Where-Object { $_.SamAccountName -ne 'krbtgt' }

$rows = foreach ($a in $accounts) {
    $risk = @(); $score = 0
    $age = if ($a.PasswordLastSet) { [int]((Get-Date) - $a.PasswordLastSet).TotalDays } else { 9999 }
    if ($a.AdminCount -eq 1) { $risk += 'PRIVILEGED'; $score += 3 }
    if ($age -gt $MaxPasswordAgeDays) { $risk += "password $age days old"; $score += 2 }
    if ($a.PasswordNeverExpires) { $risk += 'never expires'; $score += 1 }
    $enc = [int]$a.'msDS-SupportedEncryptionTypes'
    if (-not ($enc -band 0x18) -or ($enc -band 0x4)) { $risk += 'RC4 allowed'; $score += 1 }   # 0x18 = AES128|AES256, 0x4 = RC4

    [pscustomobject]@{
        Risk        = if ($score -ge 4) { 'HIGH' } elseif ($score -ge 2) { 'MEDIUM' } else { 'LOW' }
        Account     = $a.SamAccountName
        SPN         = ($a.ServicePrincipalName | Select-Object -First 2) -join ', '
        PwdAgeDays  = $age
        LastLogon   = $a.LastLogonDate
        Findings    = $risk -join ' | '
    }
}

if (-not $rows) { Write-Host 'No user accounts with SPNs found.' -ForegroundColor Green; return }
$order = @{ HIGH = 0; MEDIUM = 1; LOW = 2 }
$rows = $rows | Sort-Object @{e = { $order[$_.Risk] } }, PwdAgeDays -Descending
foreach ($r in $rows) {
    $color = @{ HIGH = 'Red'; MEDIUM = 'Yellow'; LOW = 'Gray' }[$r.Risk]
    Write-Host ("{0,-6} {1,-22} {2,5} d  {3}" -f $r.Risk, $r.Account, $r.PwdAgeDays, $r.Findings) -ForegroundColor $color
}
Write-Host ("`n{0} kerberoastable accounts, {1} HIGH." -f @($rows).Count, @($rows | Where-Object Risk -eq 'HIGH').Count) -ForegroundColor Cyan
if ($CsvPath) { $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 }
Write-Host 'Fix: move services to gMSA/dMSA, else 25+ char random passwords, AES only, remove from admin groups, delete unused SPNs.' -ForegroundColor DarkGray
