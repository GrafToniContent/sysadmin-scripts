<#
.SYNOPSIS
    Shows and (optionally) enables Microsoft Defender Attack Surface Reduction (ASR) rules.

.DESCRIPTION
    ASR rules block typical attack techniques: Office macros starting processes,
    credential theft from LSASS, obfuscated scripts, executables from e-mail ...
    They are free with Microsoft Defender Antivirus - but OFF by default.

    Default: read-only, shows the state of each rule.
    -Mode Audit : enable all listed rules in AUDIT mode (logs only, Event ID 1121/1122)
    -Mode Block : enable in BLOCK mode - only after reviewing the audit events!
    Supports -WhatIf. Run as administrator. For many devices use Intune / GPO instead.

.EXAMPLE
    .\15-Set-AsrRules.ps1                       # show state
    .\15-Set-AsrRules.ps1 -Mode Audit -WhatIf   # dry run
    .\15-Set-AsrRules.ps1 -Mode Audit
#>
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Show', 'Audit', 'Block')][string]$Mode = 'Show',
    [switch]$ShowAuditEvents
)

# Common ASR rules incl. Microsoft's standard protection rules (GUIDs from Microsoft Learn)
$rules = [ordered]@{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office apps from creating child processes'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office apps from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office apps from injecting code into other processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication app from creating child processes'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executables'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
}
$actionName = @{ 0 = 'Off'; 1 = 'Block'; 2 = 'Audit'; 5 = 'Off'; 6 = 'Warn' }   # 5 = not configured

$pref = Get-MpPreference
$current = @{}
for ($i = 0; $i -lt @($pref.AttackSurfaceReductionRules_Ids).Count; $i++) {
    $current[$pref.AttackSurfaceReductionRules_Ids[$i].ToLower()] = [int]$pref.AttackSurfaceReductionRules_Actions[$i]
}

Write-Host "`n=== Attack Surface Reduction rules ===`n" -ForegroundColor Cyan
foreach ($id in $rules.Keys) {
    $state = if ($current.ContainsKey($id)) { $actionName[$current[$id]] } else { 'Off' }
    if (-not $state) { $state = 'Off' }   # unknown action value
    $color = @{ Block = 'Green'; Audit = 'Yellow'; Warn = 'Yellow'; Off = 'Red' }[$state]
    Write-Host ('{0,-6} {1}' -f $state, $rules[$id]) -ForegroundColor $color
}

if ($Mode -ne 'Show') {
    $action = if ($Mode -eq 'Block') { 'Enabled' } else { 'AuditMode' }
    foreach ($id in $rules.Keys) {
        if ($PSCmdlet.ShouldProcess($rules[$id], "Set ASR rule to $Mode")) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $action
        }
    }
    if (-not $WhatIfPreference) { Write-Host "`nAll rules set to $Mode." -ForegroundColor Green }
}

if ($ShowAuditEvents) {
    Write-Host "`n=== ASR events (last 7 days) ===" -ForegroundColor Cyan
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1121, 1122; StartTime = (Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, @{n = 'Detail'; e = { ($_.Message -split "`n" | Select-String 'Path|Process Name|ID:' | ForEach-Object { $_.Line.Trim() }) -join ' | ' } } |
        Format-Table -Wrap
}
Write-Host "`nWorkflow: Audit for 2-4 weeks -> review events 1122 -> exclusions -> Block." -ForegroundColor DarkGray
