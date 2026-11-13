<#
.SYNOPSIS
    Applies a baseline of Microsoft 365 / Entra ID hardening measures - safely.

.DESCRIPTION
    Every measure is opt-in via -Measure and supports -WhatIf / -Confirm.
    Conditional Access policies are ALWAYS created in report-only mode -
    review the sign-in logs, then switch them on manually.

    Measures:
      DisableUserConsent      Users can no longer consent to apps (consent phishing)
      RestrictGuestInvites    Only admins + Guest Inviter role may invite guests
      RestrictUserCreation    Users can't register apps or create new tenants
      CABlockLegacyAuth       CA policy: block legacy authentication   (report-only, Entra P1)
      CAMfaAdmins             CA policy: MFA for 14 admin roles        (report-only, Entra P1)
      CAMfaAllUsers           CA policy: MFA for all users             (report-only, Entra P1)
      EnableUnifiedAuditLog   Turn on the unified audit log            (Exchange Online)
      EnableMailboxAudit      Make sure mailbox auditing is on         (Exchange Online)
      DisableSmtpAuth         Disable SMTP AUTH org-wide               (Exchange Online)
      BlockExternalForwarding Block automatic external forwarding      (Exchange Online)
      All                     Everything above

    ALWAYS exclude at least one break-glass account from CA policies (-BreakGlassUpn)!

.EXAMPLE
    # Dry run - shows what would happen, changes nothing
    .\10-Set-M365Hardening.ps1 -Measure All -BreakGlassUpn breakglass@contoso.onmicrosoft.com -WhatIf

.EXAMPLE
    .\10-Set-M365Hardening.ps1 -Measure DisableUserConsent, CABlockLegacyAuth -BreakGlassUpn bg@contoso.onmicrosoft.com

.NOTES
    Test in a test tenant first. Inform users before disabling SMTP AUTH
    (multifunction printers / scanners / old apps!). Use at your own risk.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('All', 'DisableUserConsent', 'RestrictGuestInvites', 'RestrictUserCreation',
        'CABlockLegacyAuth', 'CAMfaAdmins', 'CAMfaAllUsers',
        'EnableUnifiedAuditLog', 'EnableMailboxAudit', 'DisableSmtpAuth', 'BlockExternalForwarding')]
    [string[]]$Measure,

    [string[]]$BreakGlassUpn,

    [string]$LogPath = (Join-Path $PWD "M365-Hardening_$(Get-Date -Format 'yyyyMMdd_HHmm').log")
)

$ErrorActionPreference = 'Stop'
if ($Measure -contains 'All') {
    $Measure = 'DisableUserConsent', 'RestrictGuestInvites', 'RestrictUserCreation', 'CABlockLegacyAuth',
        'CAMfaAdmins', 'CAMfaAllUsers', 'EnableUnifiedAuditLog', 'EnableMailboxAudit', 'DisableSmtpAuth', 'BlockExternalForwarding'
}

function Write-Log([string]$Msg, [string]$Color = 'White') {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $Msg"
    Write-Host $line -ForegroundColor $Color
    Add-Content -Path $LogPath -Value $line -WhatIf:$false
}

$graphMeasures = 'DisableUserConsent', 'RestrictGuestInvites', 'RestrictUserCreation', 'CABlockLegacyAuth', 'CAMfaAdmins', 'CAMfaAllUsers'
$exoMeasures = 'EnableUnifiedAuditLog', 'EnableMailboxAudit', 'DisableSmtpAuth', 'BlockExternalForwarding'
$caMeasures = 'CABlockLegacyAuth', 'CAMfaAdmins', 'CAMfaAllUsers'

if (($Measure | Where-Object { $_ -in $caMeasures }) -and -not $BreakGlassUpn) {
    throw 'Conditional Access measures require -BreakGlassUpn (emergency access account to exclude). Lockout protection.'
}

#region --- Graph ----------------------------------------------------------------
$excludeIds = @()
if ($Measure | Where-Object { $_ -in $graphMeasures }) {
    Connect-MgGraph -NoWelcome -Scopes 'Policy.ReadWrite.Authorization', 'Policy.ReadWrite.ConditionalAccess',
        'Policy.Read.All', 'Application.Read.All', 'User.Read.All'
    Write-Log "Connected to Graph tenant $((Get-MgContext).TenantId)" 'Cyan'

    foreach ($upn in $BreakGlassUpn) {
        $u = Get-MgUser -UserId $upn -Property Id, UserPrincipalName
        $excludeIds += $u.Id
        Write-Log "Break-glass account excluded from CA: $($u.UserPrincipalName)" 'Cyan'
    }
}

$authPolicyUri = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
$caUri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'

function New-CaPolicyReportOnly([string]$Name, [hashtable]$Body) {
    $existing = Get-MgIdentityConditionalAccessPolicy -All | Where-Object DisplayName -eq $Name
    if ($existing) { Write-Log "SKIP  CA policy '$Name' already exists (state: $($existing.State))" 'DarkGray'; return }
    if ($PSCmdlet.ShouldProcess($Name, 'Create Conditional Access policy (report-only)')) {
        $Body.displayName = $Name
        $Body.state = 'enabledForReportingButNotEnforced'
        Invoke-MgGraphRequest -Method POST -Uri $caUri -Body ($Body | ConvertTo-Json -Depth 10) -ContentType 'application/json' | Out-Null
        Write-Log "DONE  CA policy '$Name' created in REPORT-ONLY mode" 'Green'
    }
}

switch ($Measure) {
    'DisableUserConsent' {
        if ($PSCmdlet.ShouldProcess('Authorization policy', 'Disable user consent for apps')) {
            $body = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() } }
            Invoke-MgGraphRequest -Method PATCH -Uri $authPolicyUri -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json'
            Write-Log 'DONE  User consent disabled. Tip: enable the admin consent workflow in Entra ID > Enterprise apps.' 'Green'
        }
    }
    'RestrictGuestInvites' {
        if ($PSCmdlet.ShouldProcess('Authorization policy', 'Restrict guest invites to admins + Guest Inviter')) {
            Invoke-MgGraphRequest -Method PATCH -Uri $authPolicyUri -Body (@{ allowInvitesFrom = 'adminsAndGuestInviters' } | ConvertTo-Json) -ContentType 'application/json'
            Write-Log 'DONE  Guest invitations restricted to admins and Guest Inviter role.' 'Green'
        }
    }
    'RestrictUserCreation' {
        if ($PSCmdlet.ShouldProcess('Authorization policy', 'Block app registration and tenant creation by users')) {
            $body = @{ defaultUserRolePermissions = @{ allowedToCreateApps = $false; allowedToCreateTenants = $false } }
            Invoke-MgGraphRequest -Method PATCH -Uri $authPolicyUri -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json'
            Write-Log 'DONE  Users can no longer register apps or create tenants.' 'Green'
        }
    }
    'CABlockLegacyAuth' {
        New-CaPolicyReportOnly 'BASE - Block legacy authentication' @{
            conditions    = @{
                users          = @{ includeUsers = @('All'); excludeUsers = $excludeIds }
                applications   = @{ includeApplications = @('All') }
                clientAppTypes = @('exchangeActiveSync', 'other')
            }
            grantControls = @{ operator = 'OR'; builtInControls = @('block') }
        }
    }
    'CAMfaAdmins' {
        # Role template IDs of privileged roles (Microsoft recommendation)
        $roles = @(
            '62e90394-69f5-4237-9190-012177145e10', # Global Administrator
            'e8611ab8-c189-46e8-94e1-60213ab1f814', # Privileged Role Administrator
            '194ae4cb-b126-40b2-bd5b-6091b380977d', # Security Administrator
            '29232cdf-9323-42fd-ade2-1d097af3e4de', # Exchange Administrator
            'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', # SharePoint Administrator
            '69091246-20e8-4a56-aa4d-066075b2a7a8', # Teams Administrator
            'fe930be7-5e62-47db-91af-98c3a49a38b1', # User Administrator
            '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', # Application Administrator
            '158c047a-c907-4556-b7ef-446551a6b5f7', # Cloud Application Administrator
            'c4e39bd9-1100-46d3-8c65-fb160da0071f', # Authentication Administrator
            'b0f54661-2d74-4c50-afa3-1ec803f12efe', # Billing Administrator
            '729827e3-9c14-49f7-bb1b-9608f156bbb8', # Helpdesk Administrator
            '966707d0-3269-4727-9be2-8c3a10f19b9d', # Password Administrator
            '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'  # Privileged Authentication Administrator
        )
        New-CaPolicyReportOnly 'BASE - Require MFA for admin roles' @{
            conditions    = @{
                users          = @{ includeRoles = $roles; excludeUsers = $excludeIds }
                applications   = @{ includeApplications = @('All') }
                clientAppTypes = @('all')
            }
            grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
        }
    }
    'CAMfaAllUsers' {
        New-CaPolicyReportOnly 'BASE - Require MFA for all users' @{
            conditions    = @{
                users          = @{ includeUsers = @('All'); excludeUsers = $excludeIds }
                applications   = @{ includeApplications = @('All') }
                clientAppTypes = @('all')
            }
            grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
        }
    }
}
#endregion

#region --- Exchange Online --------------------------------------------------------
if ($Measure | Where-Object { $_ -in $exoMeasures }) {
    Connect-ExchangeOnline -ShowBanner:$false
    Write-Log 'Connected to Exchange Online' 'Cyan'

    switch ($Measure) {
        'EnableUnifiedAuditLog' {
            if ((Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled) { Write-Log 'SKIP  Unified audit log already enabled' 'DarkGray' }
            elseif ($PSCmdlet.ShouldProcess('Organization', 'Enable unified audit log')) {
                Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
                Write-Log 'DONE  Unified audit log enabled (can take up to 60 min).' 'Green'
            }
        }
        'EnableMailboxAudit' {
            if (-not (Get-OrganizationConfig).AuditDisabled) { Write-Log 'SKIP  Mailbox auditing already on' 'DarkGray' }
            elseif ($PSCmdlet.ShouldProcess('Organization', 'Enable mailbox auditing')) {
                Set-OrganizationConfig -AuditDisabled $false
                Write-Log 'DONE  Mailbox auditing enabled.' 'Green'
            }
        }
        'DisableSmtpAuth' {
            # Show who still uses SMTP AUTH explicitly per mailbox (those keep working)
            $perMailbox = Get-CASMailbox -ResultSize Unlimited | Where-Object SmtpClientAuthenticationDisabled -eq $false
            if ($perMailbox) { Write-Log "INFO  Mailboxes with explicit SMTP AUTH exception: $($perMailbox.PrimarySmtpAddress -join ', ')" 'Yellow' }
            if ((Get-TransportConfig).SmtpClientAuthenticationDisabled) { Write-Log 'SKIP  SMTP AUTH already disabled org-wide' 'DarkGray' }
            elseif ($PSCmdlet.ShouldProcess('Organization', 'Disable SMTP AUTH org-wide')) {
                Set-TransportConfig -SmtpClientAuthenticationDisabled $true
                Write-Log 'DONE  SMTP AUTH disabled org-wide. Exceptions: Set-CASMailbox <mbx> -SmtpClientAuthenticationDisabled $false' 'Green'
            }
        }
        'BlockExternalForwarding' {
            $p = Get-HostedOutboundSpamFilterPolicy | Where-Object IsDefault
            if ($p.AutoForwardingMode -eq 'Off') { Write-Log 'SKIP  External auto-forwarding already Off' 'DarkGray' }
            elseif ($PSCmdlet.ShouldProcess($p.Identity, 'Set AutoForwardingMode Off')) {
                Set-HostedOutboundSpamFilterPolicy -Identity $p.Identity -AutoForwardingMode Off
                Write-Log 'DONE  Automatic external forwarding blocked.' 'Green'
            }
        }
    }
    Disconnect-ExchangeOnline -Confirm:$false
}
#endregion

if (Get-MgContext) { Disconnect-MgGraph | Out-Null }
Write-Log "Finished. Log: $LogPath" 'Cyan'
