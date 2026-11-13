<#
.SYNOPSIS
    Read-only security audit of a Microsoft 365 / Entra ID tenant with HTML report.

.DESCRIPTION
    Checks (each one PASS / WARN / FAIL / INFO):
      Entra ID (Microsoft Graph)
        - Security Defaults vs. Conditional Access
        - Conditional Access: legacy auth blocked? MFA for admins / all users?
        - Number of Global Admins (recommended: 2-4, incl. break-glass)
        - MFA registration of users and admins
        - User consent for apps, app registration by users, tenant creation by users
        - Guest invitation settings
        - Stale accounts (no sign-in for X days)
        - Microsoft Secure Score
      Exchange Online (optional, -IncludeExchange)
        - Unified audit log, mailbox auditing
        - SMTP AUTH disabled org-wide
        - External auto-forwarding blocked
        - Mailboxes forwarding externally
        - DKIM enabled for all domains

    Nothing is changed. Use Set-M365Hardening.ps1 for remediation.

.EXAMPLE
    .\09-Get-M365SecurityAudit.ps1 -IncludeExchange -ReportPath C:\Temp\M365-Audit.html

.NOTES
    Modules: Microsoft.Graph (Authentication, Identity.SignIns, Identity.DirectoryManagement,
             Users, Reports, Security), ExchangeOnlineManagement (for -IncludeExchange)
    Some checks need Entra ID P1/P2 (Conditional Access, sign-in activity, registration details).
    These are reported as INFO if the license is missing.
#>
[CmdletBinding()]
param(
    [switch]$IncludeExchange,
    [int]$StaleDays = 90,
    [string]$ReportPath = (Join-Path $PWD "M365-SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmm').html")
)

$ErrorActionPreference = 'Stop'
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [string]$Category, [string]$Check,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')] [string]$Status,
        [string]$Detail, [string]$Recommendation = ''
    )
    $results.Add([pscustomobject]@{
        Category = $Category; Check = $Check; Status = $Status
        Detail = $Detail; Recommendation = $Recommendation
    })
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Gray' }[$Status]
    Write-Host ("[{0}] {1} - {2}: {3}" -f $Status, $Category, $Check, $Detail) -ForegroundColor $color
}

function Invoke-Check([string]$Category, [string]$Check, [scriptblock]$Block) {
    try { & $Block }
    catch { Add-Result $Category $Check 'INFO' "Check not possible: $($_.Exception.Message)" 'Check permissions / licensing.' }
}

#region --- Connect --------------------------------------------------------------
$scopes = @(
    'Policy.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory',
    'AuditLog.Read.All', 'Reports.Read.All', 'SecurityEvents.Read.All', 'User.Read.All'
)
Connect-MgGraph -Scopes $scopes -NoWelcome
$ctx = Get-MgContext
$org = Get-MgOrganization
Write-Host "`nTenant: $($org.DisplayName) ($($ctx.TenantId))`n" -ForegroundColor Cyan
#endregion

#region --- Entra ID checks ------------------------------------------------------
$caPolicies = @()

Invoke-Check 'Entra ID' 'Security Defaults / Conditional Access' {
    $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
    try { $script:caPolicies = @(Get-MgIdentityConditionalAccessPolicy -All) } catch { $script:caPolicies = @() }
    $enabledCa = @($caPolicies | Where-Object State -eq 'enabled')

    if ($sd.IsEnabled) {
        Add-Result 'Entra ID' 'Security Defaults' 'PASS' 'Security Defaults are enabled (MFA + legacy auth blocked).' `
            'Fine for small tenants. With Entra ID P1, Conditional Access gives more control.'
    } elseif ($enabledCa.Count -gt 0) {
        Add-Result 'Entra ID' 'Security Defaults' 'INFO' "Disabled - $($enabledCa.Count) Conditional Access policies enabled."
    } else {
        Add-Result 'Entra ID' 'Security Defaults' 'FAIL' 'Neither Security Defaults nor enabled Conditional Access policies!' `
            'Enable Security Defaults immediately or create CA policies (MFA, block legacy auth).'
    }
}

Invoke-Check 'Conditional Access' 'Policies' {
    if (-not $caPolicies) { Add-Result 'Conditional Access' 'Policies' 'INFO' 'No CA policies found (or no Entra ID P1).'; return }
    $enabled = $caPolicies | Where-Object State -eq 'enabled'

    $legacy = $enabled | Where-Object {
        ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or $_.Conditions.ClientAppTypes -contains 'other') -and
        $_.GrantControls.BuiltInControls -contains 'block'
    }
    if ($legacy) { Add-Result 'Conditional Access' 'Block legacy authentication' 'PASS' ($legacy.DisplayName -join ', ') }
    else { Add-Result 'Conditional Access' 'Block legacy authentication' 'FAIL' 'No enabled policy blocks legacy auth.' 'Create CA policy: client apps "Exchange ActiveSync" + "Other clients" -> Block.' }

    $mfaAll = $enabled | Where-Object {
        $_.Conditions.Users.IncludeUsers -contains 'All' -and
        ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.AuthenticationStrength)
    }
    if ($mfaAll) { Add-Result 'Conditional Access' 'MFA for all users' 'PASS' ($mfaAll.DisplayName -join ', ') }
    else { Add-Result 'Conditional Access' 'MFA for all users' 'WARN' 'No enabled policy enforces MFA for all users.' 'Require MFA for all users (exclude break-glass accounts).' }

    $mfaAdm = $enabled | Where-Object {
        $_.Conditions.Users.IncludeRoles.Count -gt 0 -and
        ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.AuthenticationStrength)
    }
    if ($mfaAdm -or $mfaAll) { Add-Result 'Conditional Access' 'MFA for admin roles' 'PASS' 'Covered.' }
    else { Add-Result 'Conditional Access' 'MFA for admin roles' 'FAIL' 'Admins are not forced to use MFA.' 'Create CA policy for admin roles -> phishing-resistant MFA.' }

    $reportOnly = @($caPolicies | Where-Object State -eq 'enabledForReportingButNotEnforced')
    if ($reportOnly) { Add-Result 'Conditional Access' 'Report-only policies' 'INFO' "$($reportOnly.Count) in report-only: $($reportOnly.DisplayName -join ', ')" 'Review sign-in logs, then switch to On.' }
}

Invoke-Check 'Entra ID' 'Global Administrators' {
    $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'"
    $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All)
    $names = ($members | ForEach-Object { $_.AdditionalProperties.userPrincipalName }) -join ', '
    $n = $members.Count
    if ($n -lt 2) { Add-Result 'Entra ID' 'Global Administrators' 'WARN' "$n Global Admin(s): $names" 'At least 2 (incl. one break-glass account).' }
    elseif ($n -le 4) { Add-Result 'Entra ID' 'Global Administrators' 'PASS' "$n Global Admins: $names" }
    else { Add-Result 'Entra ID' 'Global Administrators' 'FAIL' "$n Global Admins: $names" 'Reduce to max. 4, use least-privilege roles (Exchange Admin, User Admin ...).' }
}

Invoke-Check 'Entra ID' 'MFA registration' {
    $reg = @(Get-MgReportAuthenticationMethodUserRegistrationDetail -All)
    $members = @($reg | Where-Object UserType -eq 'member')
    $noMfa = @($members | Where-Object { -not $_.IsMfaRegistered })
    $adminNoMfa = @($reg | Where-Object { $_.IsAdmin -and -not $_.IsMfaRegistered })

    $pct = if ($members.Count) { [math]::Round(100 * ($members.Count - $noMfa.Count) / $members.Count, 1) } else { 0 }
    $status = if ($pct -ge 98) { 'PASS' } elseif ($pct -ge 85) { 'WARN' } else { 'FAIL' }
    Add-Result 'Entra ID' 'MFA registration (users)' $status "$pct % registered - $($noMfa.Count) of $($members.Count) without MFA." `
        'Run a registration campaign; check the list of users without MFA.'

    if ($adminNoMfa) { Add-Result 'Entra ID' 'MFA registration (admins)' 'FAIL' ("Admins without MFA: " + ($adminNoMfa.UserPrincipalName -join ', ')) 'Register MFA for every admin immediately.' }
    else { Add-Result 'Entra ID' 'MFA registration (admins)' 'PASS' 'All admins have MFA registered.' }
}

Invoke-Check 'Entra ID' 'Authorization policy' {
    $ap = Get-MgPolicyAuthorizationPolicy
    $perm = $ap.DefaultUserRolePermissions

    $grant = @($perm.PermissionGrantPoliciesAssigned)
    if ($grant -match 'microsoft-user-default-legacy') {
        Add-Result 'Entra ID' 'User consent for apps' 'FAIL' 'Users may consent to any app (consent phishing risk).' 'Disable user consent or allow only verified publishers + admin consent workflow.'
    } elseif ($grant -match 'microsoft-user-default-low') {
        Add-Result 'Entra ID' 'User consent for apps' 'WARN' 'Users may consent to verified publishers (low-risk permissions).'
    } else {
        Add-Result 'Entra ID' 'User consent for apps' 'PASS' 'User consent disabled.'
    }

    if ($perm.AllowedToCreateApps) { Add-Result 'Entra ID' 'Users can register apps' 'WARN' 'Enabled.' 'Set "Users can register applications" to No.' }
    else { Add-Result 'Entra ID' 'Users can register apps' 'PASS' 'Disabled.' }

    if ($perm.AllowedToCreateTenants) { Add-Result 'Entra ID' 'Users can create tenants' 'WARN' 'Enabled.' 'Set "Restrict non-admin users from creating tenants" to Yes.' }
    else { Add-Result 'Entra ID' 'Users can create tenants' 'PASS' 'Disabled.' }

    switch ($ap.AllowInvitesFrom) {
        'everyone' { Add-Result 'Entra ID' 'Guest invitations' 'FAIL' 'Everyone (incl. guests) can invite guests.' 'Restrict to admins and Guest Inviter role.' }
        'adminsGuestInvitersAndAllMembers' { Add-Result 'Entra ID' 'Guest invitations' 'WARN' 'All members can invite guests.' 'Restrict to admins and Guest Inviter role.' }
        default { Add-Result 'Entra ID' 'Guest invitations' 'PASS' "Restricted ($($ap.AllowInvitesFrom))." }
    }
}

Invoke-Check 'Entra ID' 'Stale accounts' {
    $cutoff = (Get-Date).AddDays(-$StaleDays)
    $users = Get-MgUser -All -Filter 'accountEnabled eq true' -Property UserPrincipalName, UserType, SignInActivity, CreatedDateTime
    $stale = @($users | Where-Object {
        $last = $_.SignInActivity.LastSignInDateTime
        ($last -and $last -lt $cutoff) -or (-not $last -and $_.CreatedDateTime -lt $cutoff)
    })
    $staleGuests = @($stale | Where-Object UserType -eq 'Guest')
    $status = if ($stale.Count -eq 0) { 'PASS' } else { 'WARN' }
    Add-Result 'Entra ID' "Enabled accounts without sign-in > $StaleDays days" $status `
        "$($stale.Count) accounts ($($staleGuests.Count) guests)." 'Disable or delete; check for shared mailboxes with enabled login.'
    $script:staleList = $stale
}

Invoke-Check 'Entra ID' 'Secure Score' {
    $ss = Get-MgSecuritySecureScore -Top 1
    $pct = [math]::Round(100 * $ss.CurrentScore / $ss.MaxScore, 1)
    $status = if ($pct -ge 70) { 'PASS' } elseif ($pct -ge 45) { 'WARN' } else { 'FAIL' }
    Add-Result 'Entra ID' 'Microsoft Secure Score' $status "$($ss.CurrentScore) / $($ss.MaxScore) ($pct %)" 'See security.microsoft.com -> Secure Score -> Recommended actions.'
}
#endregion

#region --- Exchange Online checks -----------------------------------------------
if ($IncludeExchange) {
    Connect-ExchangeOnline -ShowBanner:$false

    Invoke-Check 'Exchange Online' 'Unified audit log' {
        $cfg = Get-AdminAuditLogConfig
        if ($cfg.UnifiedAuditLogIngestionEnabled) { Add-Result 'Exchange Online' 'Unified audit log' 'PASS' 'Enabled.' }
        else { Add-Result 'Exchange Online' 'Unified audit log' 'FAIL' 'Disabled - no forensics possible after an incident!' 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' }
    }

    Invoke-Check 'Exchange Online' 'Mailbox auditing' {
        if ((Get-OrganizationConfig).AuditDisabled) { Add-Result 'Exchange Online' 'Mailbox auditing' 'FAIL' 'Disabled org-wide.' 'Set-OrganizationConfig -AuditDisabled $false' }
        else { Add-Result 'Exchange Online' 'Mailbox auditing' 'PASS' 'Enabled by default.' }
    }

    Invoke-Check 'Exchange Online' 'SMTP AUTH' {
        if ((Get-TransportConfig).SmtpClientAuthenticationDisabled) { Add-Result 'Exchange Online' 'SMTP AUTH (org-wide)' 'PASS' 'Disabled.' }
        else { Add-Result 'Exchange Online' 'SMTP AUTH (org-wide)' 'WARN' 'Enabled org-wide (basic auth for SMTP submission).' 'Disable org-wide, enable only per mailbox where needed (scanners, apps).' }
    }

    Invoke-Check 'Exchange Online' 'External auto-forwarding' {
        $p = Get-HostedOutboundSpamFilterPolicy | Where-Object IsDefault
        if ($p.AutoForwardingMode -eq 'On') { Add-Result 'Exchange Online' 'External auto-forwarding' 'FAIL' 'Allowed (On).' 'Set AutoForwardingMode to Off (data exfiltration / BEC).' }
        else { Add-Result 'Exchange Online' 'External auto-forwarding' 'PASS' "Mode: $($p.AutoForwardingMode) (Automatic = blocked)." }
    }

    Invoke-Check 'Exchange Online' 'Mailbox forwarding' {
        $fwd = @(Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress, ForwardingAddress |
            Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress })
        if ($fwd) {
            $list = ($fwd | ForEach-Object { "$($_.UserPrincipalName) -> $($_.ForwardingSmtpAddress)$($_.ForwardingAddress)" }) -join '; '
            Add-Result 'Exchange Online' 'Mailbox forwarding' 'WARN' "$($fwd.Count) mailbox(es): $list" 'Verify each forwarding is legitimate.'
        } else { Add-Result 'Exchange Online' 'Mailbox forwarding' 'PASS' 'No mailbox-level forwarding.' }
    }

    Invoke-Check 'Exchange Online' 'DKIM' {
        $dkim = Get-DkimSigningConfig | Where-Object { $_.Domain -notlike '*.onmicrosoft.com' }
        $off = @($dkim | Where-Object { -not $_.Enabled })
        if ($off) { Add-Result 'Exchange Online' 'DKIM signing' 'WARN' ("Not enabled for: " + ($off.Domain -join ', ')) 'Publish CNAMEs and enable DKIM (plus DMARC policy).' }
        else { Add-Result 'Exchange Online' 'DKIM signing' 'PASS' 'Enabled for all custom domains.' }
    }

    Disconnect-ExchangeOnline -Confirm:$false
}
#endregion

#region --- HTML report ----------------------------------------------------------
$enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
$count = $results | Group-Object Status -AsHashTable -AsString
$c = @{}; foreach ($s in 'PASS', 'WARN', 'FAIL', 'INFO') { $c[$s] = if ($count -and $count[$s]) { $count[$s].Count } else { 0 } }

$rows = foreach ($r in ($results | Sort-Object @{ e = { @{ FAIL = 0; WARN = 1; INFO = 2; PASS = 3 }[$_.Status] } }, Category)) {
    "<tr><td><span class='b $($r.Status)'>$($r.Status)</span></td><td>$(& $enc $r.Category)</td><td>$(& $enc $r.Check)</td><td>$(& $enc $r.Detail)</td><td>$(& $enc $r.Recommendation)</td></tr>"
}

$html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>M365 Security Audit - $(& $enc $org.DisplayName)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#222}
h1{margin-bottom:4px} .meta{color:#666;margin-bottom:20px}
.sum span{display:inline-block;padding:10px 18px;margin-right:8px;border-radius:6px;font-weight:600}
table{border-collapse:collapse;width:100%;margin-top:20px;font-size:14px}
th,td{border-bottom:1px solid #ddd;padding:8px;text-align:left;vertical-align:top} th{background:#f4f4f4}
.b{padding:2px 8px;border-radius:4px;font-weight:600;font-size:12px}
.PASS{background:#d8f3dc;color:#1b5e20}.WARN{background:#fff3cd;color:#7a5c00}
.FAIL{background:#f8d7da;color:#842029}.INFO{background:#e7e7e7;color:#444}
</style></head><body>
<h1>Microsoft 365 Security Audit</h1>
<div class="meta">Tenant: $(& $enc $org.DisplayName) &middot; $($ctx.TenantId) &middot; $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; by $(& $enc $ctx.Account)</div>
<div class="sum"><span class="FAIL">FAIL: $($c.FAIL)</span><span class="WARN">WARN: $($c.WARN)</span><span class="PASS">PASS: $($c.PASS)</span><span class="INFO">INFO: $($c.INFO)</span></div>
<table><tr><th>Status</th><th>Category</th><th>Check</th><th>Finding</th><th>Recommendation</th></tr>
$($rows -join "`n")
</table></body></html>
"@

$html | Out-File -FilePath $ReportPath -Encoding utf8
if ($script:staleList) {
    $script:staleList | Select-Object UserPrincipalName, UserType, CreatedDateTime,
        @{ n = 'LastSignIn'; e = { $_.SignInActivity.LastSignInDateTime } } |
        Export-Csv -Path ($ReportPath -replace '\.html$', '_StaleAccounts.csv') -NoTypeInformation -Encoding UTF8
}
Write-Host "`nReport: $ReportPath" -ForegroundColor Green
Disconnect-MgGraph | Out-Null
#endregion
