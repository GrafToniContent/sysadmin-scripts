<#
.SYNOPSIS
    Checks the SharePoint / OneDrive sharing settings of your Microsoft 365 tenant.

.DESCRIPTION
    "Anyone with the link" sharing is convenient - and the easiest way to leak data.
    This read-only script reads the tenant-wide SharePoint settings via Microsoft Graph
    and rates them:
      - Sharing capability (Anyone / New+existing guests / Existing guests / Only internal)
      - Resharing by external users
      - Domain allow / block list
      - Unmanaged device / idle session settings (where exposed)
      - OneDrive + SharePoint Loop / site creation by users

    Permission: SharePointTenantSettings.Read.All

.EXAMPLE
    .\19-Get-M365SharingSettings.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Connect-MgGraph -Scopes 'SharePointTenantSettings.Read.All' -NoWelcome

$s = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings'

function Show([string]$Check, [string]$Status, [string]$Detail, [string]$Fix = '') {
    $c = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Gray' }[$Status]
    Write-Host ("[{0}] {1,-38} {2}" -f $Status, $Check, $Detail) -ForegroundColor $c
    if ($Fix -and $Status -ne 'PASS') { Write-Host ("       -> {0}" -f $Fix) -ForegroundColor DarkGray }
}

Write-Host "`n=== SharePoint / OneDrive sharing settings ===`n" -ForegroundColor Cyan

switch ($s.sharingCapability) {
    'externalUserAndGuestSharing' { Show 'External sharing' 'FAIL' 'Anyone links allowed (no sign-in needed)' 'Limit to "New and existing guests" or stricter.' }
    'externalUserSharingOnly'     { Show 'External sharing' 'WARN' 'New and existing guests' 'OK for many orgs - make sure guest access reviews exist.' }
    'existingExternalUserSharingOnly' { Show 'External sharing' 'PASS' 'Existing guests only' }
    'disabled'                    { Show 'External sharing' 'PASS' 'Only people in your organization' }
    default                       { Show 'External sharing' 'INFO' $s.sharingCapability }
}

if ($s.isResharingByExternalUsersEnabled) { Show 'Guests can reshare' 'WARN' 'Enabled' 'Disable: guests should not share your content further.' }
else { Show 'Guests can reshare' 'PASS' 'Disabled' }

switch ($s.sharingDomainRestrictionMode) {
    'allowList' { Show 'Domain restriction' 'PASS' ("Allow list: " + ($s.sharingAllowedDomainList -join ', ')) }
    'blockList' { Show 'Domain restriction' 'INFO' ("Block list: " + ($s.sharingBlockedDomainList -join ', ')) }
    default     { Show 'Domain restriction' 'WARN' 'None' 'Consider an allow list for partner domains.' }
}

if ($s.isRequireAcceptingUserToMatchInvitedUserEnabled) { Show 'Guest must match invited account' 'PASS' 'Enabled' }
else { Show 'Guest must match invited account' 'WARN' 'Disabled' 'Enable so invitations cannot be redeemed by another account.' }

if ($s.isSiteCreationEnabled) { Show 'Users can create sites' 'INFO' 'Enabled' 'Fine if you have a governance process.' }
else { Show 'Users can create sites' 'PASS' 'Disabled' }

if ($s.isUnmanagedSyncAppForTenantRestricted) { Show 'Sync on unmanaged devices' 'PASS' 'Restricted' }
else { Show 'Sync on unmanaged devices' 'WARN' 'Allowed' 'Restrict OneDrive sync to domain-joined / compliant devices.' }

if ($s.idleSessionSignOut -and $s.idleSessionSignOut.isEnabled) { Show 'Idle session sign-out' 'PASS' 'Enabled' }
else { Show 'Idle session sign-out' 'WARN' 'Disabled' 'Sign out idle browser sessions on unmanaged devices.' }

Write-Host "`nNext step: review existing Anyone links per site (SharePoint admin center > Reports)." -ForegroundColor DarkGray
Disconnect-MgGraph | Out-Null
