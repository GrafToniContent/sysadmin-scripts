<#
.SYNOPSIS
    Read-only Windows 11 hardening audit - finds the "ghosts" before you harden anything.

.DESCRIPTION
    Checks common hardening settings and reports OK / HAUNTED / UNKNOWN for each.
    The script CHANGES NOTHING. Audit first, harden second - and test every change
    before you roll it out, because hardening settings can break applications.

    Managed environments: implement fixes with the Microsoft Security Baselines
    (Group Policy / Intune security baselines, Security Compliance Toolkit).
    Unmanaged PCs: tools like NoID Privacy (open source) can apply a hardening set -
    read their documentation and restrictions first (e.g. no domain-joined systems).

.PARAMETER HtmlReport
    Optional path for an HTML report, e.g. .\hardening-report.html

.EXAMPLE
    .\07-Get-HardeningAudit.ps1

.EXAMPLE
    .\07-Get-HardeningAudit.ps1 -HtmlReport .\hardening-report.html

.NOTES
    Graf Toni Content - "Automate it once. Never do it again."
    Run as administrator on Windows 11.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$HtmlReport
)

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

# Each check returns $true (OK), $false (HAUNTED) or throws (UNKNOWN)
$checks = [ordered]@{
    'SMBv1 server disabled' = @{
        Test = { -not (Get-SmbServerConfiguration).EnableSMB1Protocol }
        Fix  = 'Disable SMBv1 (Disable-WindowsOptionalFeature SMB1Protocol)' }
    'SMB signing required' = @{
        Test = { (Get-SmbServerConfiguration).RequireSecuritySignature }
        Fix  = 'Require SMB signing via baseline/GPO' }
    'Firewall on (all profiles)' = @{
        Test = { (Get-NetFirewallProfile).Enabled -notcontains 'False' }
        Fix  = 'Enable Windows Firewall for Domain, Private and Public' }
    'Defender real-time protection' = @{
        Test = { (Get-MpComputerStatus).RealTimeProtectionEnabled }
        Fix  = 'Enable Defender real-time protection' }
    'Defender tamper protection' = @{
        Test = { (Get-MpComputerStatus).IsTamperProtected }
        Fix  = 'Enable tamper protection (Windows Security / Intune)' }
    'BitLocker on C:' = @{
        Test = { (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq 'On' }
        Fix  = 'Enable BitLocker and escrow the recovery key' }
    'Secure Boot' = @{
        Test = { Confirm-SecureBootUEFI }
        Fix  = 'Enable Secure Boot in UEFI' }
    'LSA protection (RunAsPPL)' = @{
        Test = { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL') -ge 1 }
        Fix  = 'Enable LSA protection - test drivers/plugins first' }
    'Credential Guard running' = @{
        Test = { (Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard).SecurityServicesRunning -contains 1 }
        Fix  = 'Enable Credential Guard (VBS) via baseline/Intune' }
    'WDigest cleartext off' = @{
        Test = { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') -ne 1 }
        Fix  = 'Set WDigest UseLogonCredential to 0' }
    'LLMNR disabled' = @{
        Test = { (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -eq 0 }
        Fix  = 'Disable multicast name resolution via GPO/Intune' }
    'PowerShell 2.0 not installed' = @{
        Test = {
            $f = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
            -not $f -or $f.State -ne 'Enabled' }
        Fix  = 'Remove the PowerShell 2.0 feature' }
    'UAC enabled' = @{
        Test = { (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -eq 1 }
        Fix  = 'Enable UAC (EnableLUA = 1)' }
    'RDP requires NLA' = @{
        Test = {
            $rdpOff = (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 1
            $nla    = (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication') -eq 1
            $rdpOff -or $nla }
        Fix  = 'Require Network Level Authentication for RDP' }
}

$results = foreach ($name in $checks.Keys) {
    $status = try {
        if (& $checks[$name].Test) { 'OK' } else { 'HAUNTED' }
    } catch { 'UNKNOWN' }

    [pscustomobject]@{
        Check  = $name
        Status = $status
        Fix    = if ($status -eq 'OK') { '' } else { $checks[$name].Fix }
    }
}

foreach ($r in $results) {
    $color = switch ($r.Status) { 'OK' { 'Green' } 'HAUNTED' { 'Red' } default { 'Yellow' } }
    Write-Host ('{0,-32} {1,-8} {2}' -f $r.Check, $r.Status, $r.Fix) -ForegroundColor $color
}

$ghosts = @($results | Where-Object Status -eq 'HAUNTED').Count
Write-Host "`n$ghosts ghost(s) found. Audit first. Harden second. Test every change." -ForegroundColor Cyan

if ($HtmlReport) {
    $results | ConvertTo-Html -Title 'Hardening Audit' -PreContent "<h2>Hardening audit - $env:COMPUTERNAME - $(Get-Date -Format g)</h2>" |
        Out-File -FilePath $HtmlReport -Encoding UTF8
    Write-Host "Report: $HtmlReport"
}

$results
