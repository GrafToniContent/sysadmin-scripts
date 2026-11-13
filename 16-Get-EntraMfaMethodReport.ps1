<#
.SYNOPSIS
    Shows HOW your users do MFA - and who still relies on SMS / phone calls only.

.DESCRIPTION
    "Everyone has MFA" is not the same as "everyone has strong MFA".
    SMS and voice can be SIM-swapped or phished; Authenticator push with number
    matching is better, FIDO2 / passkeys / Windows Hello for Business are phishing-resistant.

    Reports per user:
      Strength = None | Weak (SMS/voice only) | Standard (Authenticator/TOTP) | PhishingResistant
    Admins with anything less than phishing-resistant are flagged.

    Read-only. Permission: AuditLog.Read.All (Entra ID P1 needed for registration details).

.EXAMPLE
    .\16-Get-EntraMfaMethodReport.ps1 -CsvPath C:\Temp\mfa-methods.csv
#>
[CmdletBinding()]
param(
    [string]$CsvPath = (Join-Path $PWD "Entra-MfaMethods_$(Get-Date -Format 'yyyyMMdd').csv"),
    [switch]$IncludeGuests
)

$ErrorActionPreference = 'Stop'
Connect-MgGraph -Scopes 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All' -NoWelcome

$phishingResistant = 'fido2', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello',
                     'windowsHelloForBusiness', 'x509CertificateMultiFactor'
$standard = 'microsoftAuthenticatorPush', 'softwareOneTimePasscode', 'hardwareOneTimePasscode', 'microsoftAuthenticatorPasswordless'
$weak = 'mobilePhone', 'alternateMobilePhone', 'officePhone', 'sms', 'voice'

$reg = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
if (-not $IncludeGuests) { $reg = $reg | Where-Object UserType -eq 'member' }

$rows = foreach ($u in $reg) {
    $m = @($u.MethodsRegistered)
    $strength = if ($m | Where-Object { $_ -in $phishingResistant }) { 'PhishingResistant' }
                elseif ($m | Where-Object { $_ -in $standard }) { 'Standard' }
                elseif ($m | Where-Object { $_ -in $weak }) { 'Weak' }
                else { 'None' }
    $flag = if ($u.IsAdmin -and $strength -ne 'PhishingResistant') { 'ADMIN NOT PHISHING-RESISTANT' }
            elseif ($strength -in 'None', 'Weak') { 'UPGRADE' } else { '' }
    [pscustomobject]@{
        User = $u.UserPrincipalName; IsAdmin = $u.IsAdmin; Strength = $strength
        Methods = $m -join ', '; Default = $u.DefaultMfaMethod; Flag = $flag
    }
}

$summary = $rows | Group-Object Strength | Sort-Object Name | Select-Object Name, Count
Write-Host "`nMFA strength across $(@($rows).Count) users:" -ForegroundColor Cyan
$summary | Format-Table -AutoSize

$problems = $rows | Where-Object Flag | Sort-Object @{e = { -not $_.IsAdmin } }, Strength
if ($problems) {
    Write-Host "Needs attention:" -ForegroundColor Yellow
    $problems | Format-Table User, IsAdmin, Strength, Methods, Flag -AutoSize -Wrap
} else {
    Write-Host 'No weak MFA found.' -ForegroundColor Green
}

$rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Host "CSV: $CsvPath" -ForegroundColor Green
Write-Host 'Tip: use Authentication Strengths in Conditional Access to REQUIRE phishing-resistant MFA for admins.' -ForegroundColor DarkGray
Disconnect-MgGraph | Out-Null
