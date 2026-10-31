<#
.SYNOPSIS
    Exports all Entra ID (Azure AD) users to CSV with Microsoft Graph PowerShell.

.DESCRIPTION
    Replacement for the old AzureAD / MSOnline way:

        Connect-AzureAD          ->  Connect-MgGraph -Scopes 'User.Read.All'
        Get-AzureADUser -All     ->  Get-MgUser -All -Property ...

    Graph only returns a few properties by default - request what you need with -Property.

.EXAMPLE
    Install-Module Microsoft.Graph.Users -Scope CurrentUser   # once
    .\03-Export-EntraUsers-Graph.ps1 -OutFile .\entra-users.csv

.NOTES
    Graf Toni Content - "Automate it once. Never do it again."
#>
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users
[CmdletBinding()]
param(
    [string]$OutFile = '.\entra-users.csv'
)

Connect-MgGraph -Scopes 'User.Read.All' -NoWelcome

$props = 'DisplayName', 'UserPrincipalName', 'AccountEnabled', 'Department', 'JobTitle', 'CreatedDateTime'

Get-MgUser -All -Property $props |
    Select-Object $props |
    Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8

Write-Host "Exported to $OutFile" -ForegroundColor Green
Disconnect-MgGraph | Out-Null
