<#
.SYNOPSIS
    Creates Active Directory users in bulk from a CSV file.

.DESCRIPTION
    Reads FirstName, LastName, Department and Title from a CSV file, builds the username
    (first letter of first name + last name, umlauts transliterated), skips accounts that
    already exist, sets a random initial password (must be changed at next logon) and
    exports the initial passwords to a CSV file for secure handover.

    IMPORTANT: Delete the password file after handover!

.PARAMETER CsvPath
    Path to the CSV file with the columns FirstName, LastName, Department, Title.

.PARAMETER TargetOU
    Distinguished name of the OU where the accounts are created.

.PARAMETER UpnSuffix
    UPN suffix, e.g. contoso.com

.PARAMETER PasswordFile
    Where the initial passwords are written. Default: .\initial-passwords.csv

.EXAMPLE
    .\01-New-BulkADUsers.ps1 -CsvPath .\01-newusers-sample.csv `
        -TargetOU 'OU=Users,OU=Company,DC=lab,DC=local' -UpnSuffix 'lab.local' -WhatIf

.NOTES
    Graf Toni Content - "Automate it once. Never do it again."
    Test in a lab environment first. Requires the ActiveDirectory module (RSAT).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$CsvPath,
    [Parameter(Mandatory)][string]$TargetOU,
    [Parameter(Mandatory)][string]$UpnSuffix,
    [string]$PasswordFile = '.\initial-passwords.csv'
)

Import-Module ActiveDirectory -ErrorAction Stop

function New-RandomPassword {
    # Guarantees upper, lower, digit and special character (AD complexity rules).
    # Get-Random is fine for one-time initial passwords that must be changed at first logon.
    param([int]$Length = 16)
    $sets = 'ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!$%&*?#+'
    $pw   = foreach ($s in $sets) { $s[(Get-Random -Maximum $s.Length)] }
    $all  = -join $sets
    $pw  += 1..($Length - $sets.Count) | ForEach-Object { $all[(Get-Random -Maximum $all.Length)] }
    -join ($pw | Sort-Object { Get-Random })
}

function ConvertTo-SamAccountName {
    param([string]$FirstName, [string]$LastName)
    $sam = ($FirstName.Substring(0, 1) + $LastName).ToLower()
    $sam = $sam -replace [char]0xE4, 'ae' -replace [char]0xF6, 'oe' -replace [char]0xFC, 'ue' -replace [char]0xDF, 'ss'   # ae oe ue ss
    $sam = $sam -replace '[^a-z0-9.\-]', ''
    if ($sam.Length -gt 20) { $sam = $sam.Substring(0, 20) }   # sAMAccountName limit
    $sam
}

$users = Import-Csv -Path $CsvPath

foreach ($u in $users) {
    if ([string]::IsNullOrWhiteSpace($u.FirstName) -or [string]::IsNullOrWhiteSpace($u.LastName)) {
        Write-Warning "Row without first or last name - skipped"
        continue
    }

    $sam = ConvertTo-SamAccountName -FirstName $u.FirstName.Trim() -LastName $u.LastName.Trim()

    if (Get-ADUser -Filter "SamAccountName -eq '$sam'") {
        Write-Warning "$sam already exists - skipped"
        continue
    }

    $plain  = New-RandomPassword
    $params = @{
        Name                  = "$($u.FirstName) $($u.LastName)"
        GivenName             = $u.FirstName
        Surname               = $u.LastName
        DisplayName           = "$($u.FirstName) $($u.LastName)"
        SamAccountName        = $sam
        UserPrincipalName     = "$sam@$UpnSuffix"
        Department            = $u.Department
        Title                 = $u.Title
        Path                  = $TargetOU
        AccountPassword       = (ConvertTo-SecureString $plain -AsPlainText -Force)
        ChangePasswordAtLogon = $true
        Enabled               = $true
    }
    # remove empty optional values (e.g. no department in the CSV)
    foreach ($k in @($params.Keys)) {
        if ($params[$k] -is [string] -and [string]::IsNullOrWhiteSpace($params[$k])) { $params.Remove($k) }
    }

    if ($PSCmdlet.ShouldProcess($sam, 'Create AD user')) {
        try {
            New-ADUser @params -ErrorAction Stop
            [pscustomobject]@{ User = $sam; InitialPassword = $plain } |
                Export-Csv -Path $PasswordFile -Append -NoTypeInformation
            Write-Host "Created $sam" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to create $sam : $($_.Exception.Message)"
        }
    }
}

Write-Host "Done. Hand over $PasswordFile securely - then delete it." -ForegroundColor Cyan
