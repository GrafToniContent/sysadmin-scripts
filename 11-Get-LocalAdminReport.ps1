<#
.SYNOPSIS
    Who is local administrator on your Windows 11 PCs?

.DESCRIPTION
    Users with local admin rights can disable Defender, install anything and dump
    credentials. This script queries the local Administrators group (SID S-1-5-32-544,
    works on every language) on one or many computers via PowerShell Remoting
    and flags every member that is not on your allow list.

    Read-only. Requires WinRM / PowerShell Remoting on the targets.

.EXAMPLE
    .\11-Get-LocalAdminReport.ps1 -ComputerName PC01,PC02
.EXAMPLE
    # all enabled Windows 11 computers from AD
    $pcs = (Get-ADComputer -Filter "OperatingSystem -like 'Windows 11*' -and Enabled -eq 'True'").Name
    .\11-Get-LocalAdminReport.ps1 -ComputerName $pcs -Allowed 'CONTOSO\Domain Admins','CONTOSO\PC-Admins'
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName = $env:COMPUTERNAME,
    # Members that are expected (built-in Administrator, LAPS account, admin groups ...)
    [string[]]$Allowed = @('*\Administrator', '*\Domain Admins', '*\Domänen-Admins'),
    [string]$CsvPath = (Join-Path $PWD "LocalAdmins_$(Get-Date -Format 'yyyyMMdd').csv")
)

$scriptBlock = {
    try {
        Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
            Select-Object @{n = 'Member'; e = { $_.Name } }, ObjectClass, PrincipalSource
    } catch {
        # Fallback for orphaned SIDs that break Get-LocalGroupMember
        $grp = [ADSI]"WinNT://./$((Get-CimInstance Win32_Group -Filter "SID='S-1-5-32-544'").Name),group"
        $grp.psbase.Invoke('Members') | ForEach-Object {
            [pscustomobject]@{ Member = ([ADSI]$_).InvokeGet('AdsPath') -replace '^WinNT://', '' -replace '/', '\'; ObjectClass = ([ADSI]$_).SchemaClassName; PrincipalSource = '?' }
        }
    }
}

$rows = foreach ($pc in $ComputerName) {
    try {
        $members = if ($pc -eq $env:COMPUTERNAME) { & $scriptBlock } else { Invoke-Command -ComputerName $pc -ScriptBlock $scriptBlock -ErrorAction Stop }
        foreach ($m in $members) {
            $ok = [bool]($Allowed | Where-Object { $m.Member -like $_ })
            [pscustomobject]@{
                Computer = $pc; Member = $m.Member; Type = $m.ObjectClass; Source = $m.PrincipalSource
                Status = if ($ok) { 'Expected' } else { 'REVIEW' }
            }
        }
    } catch {
        [pscustomobject]@{ Computer = $pc; Member = ''; Type = ''; Source = ''; Status = "ERROR: $($_.Exception.Message)" }
    }
}

$review = $rows | Where-Object Status -eq 'REVIEW'
$rows | Sort-Object Status, Computer | Format-Table Computer, Member, Type, Source, Status -AutoSize
$rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

Write-Host ("{0} computers checked - {1} unexpected local admins on {2} PCs." -f @($ComputerName).Count, @($review).Count, @($review.Computer | Sort-Object -Unique).Count) -ForegroundColor $(if ($review) { 'Yellow' } else { 'Green' })
Write-Host "CSV: $CsvPath"
Write-Host 'Fix: remove users from local admins, manage the group via Intune (Account protection) or GPO Restricted Groups, use Windows LAPS for the built-in admin.' -ForegroundColor DarkGray
