<#
.SYNOPSIS
    BitLocker is on - but is the recovery key actually backed up?

.DESCRIPTION
    A BitLocker-encrypted laptop without a backed-up recovery key is a laptop
    you lose after the next firmware update or TPM reset.

    Local mode (default): checks every fixed volume on this PC
      - protection status and encryption method (XTS-AES 256 recommended)
      - recovery password protector present?
      - backup to Entra ID (event 845) or Active Directory (event 784) found in the
        BitLocker management log?
    AD mode (-ActiveDirectory): lists all enabled Windows computers in AD
      without a single msFVE-RecoveryInformation object (needs RSAT AD module and read rights).

    Read-only. Run as administrator for local mode.

.EXAMPLE
    .\18-Test-BitLockerKeyBackup.ps1
.EXAMPLE
    .\18-Test-BitLockerKeyBackup.ps1 -ActiveDirectory -SearchBase 'OU=Clients,DC=contoso,DC=local'
#>
[CmdletBinding()]
param(
    [switch]$ActiveDirectory,
    [string]$SearchBase
)

if ($ActiveDirectory) {
    Import-Module ActiveDirectory -ErrorAction Stop
    $p = @{ Filter = "Enabled -eq 'True' -and OperatingSystem -like 'Windows*'"; Properties = 'OperatingSystem', 'LastLogonDate' }
    if ($SearchBase) { $p.SearchBase = $SearchBase }
    $computers = Get-ADComputer @p
    $missing = foreach ($c in $computers) {
        $keys = Get-ADObject -SearchBase $c.DistinguishedName -Filter "objectClass -eq 'msFVE-RecoveryInformation'" -ErrorAction SilentlyContinue
        if (-not $keys) { [pscustomobject]@{ Computer = $c.Name; OS = $c.OperatingSystem; LastLogon = $c.LastLogonDate } }
    }
    $missing | Sort-Object LastLogon -Descending | Format-Table -AutoSize
    Write-Host ("{0} of {1} computers have NO BitLocker recovery key in AD." -f @($missing).Count, @($computers).Count) -ForegroundColor $(if ($missing) { 'Yellow' } else { 'Green' })
    return
}

$events = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'; Id = 845, 784 } -ErrorAction SilentlyContinue

foreach ($v in Get-BitLockerVolume | Where-Object VolumeType -ne 'Removable') {
    $rp = $v.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword'
    $tpm = $v.KeyProtector | Where-Object KeyProtectorType -like 'Tpm*'
    Write-Host "`n=== $($v.MountPoint) ($($v.VolumeType)) ===" -ForegroundColor Cyan

    if ($v.ProtectionStatus -eq 'On') { Write-Host "[PASS] Protection on ($($v.EncryptionMethod), $($v.EncryptionPercentage) %)" -ForegroundColor Green }
    else { Write-Host "[FAIL] Protection $($v.ProtectionStatus) - volume status $($v.VolumeStatus)" -ForegroundColor Red; continue }

    if ($v.EncryptionMethod -notlike 'XtsAes*') { Write-Host "[WARN] Encryption method $($v.EncryptionMethod) - XTS-AES 128/256 recommended" -ForegroundColor Yellow }
    if ($v.VolumeType -eq 'OperatingSystem' -and -not $tpm) { Write-Host '[WARN] No TPM protector on OS volume' -ForegroundColor Yellow }

    if (-not $rp) { Write-Host '[FAIL] No recovery password protector - nothing to back up!' -ForegroundColor Red; continue }
    foreach ($k in $rp) {
        $backup = $events | Where-Object { $_.Message -match [regex]::Escape($k.KeyProtectorId.Trim('{}')) } | Select-Object -First 1
        if ($backup) {
            $target = if ($backup.Id -eq 845) { 'Entra ID' } else { 'Active Directory' }
            Write-Host "[PASS] Recovery key $($k.KeyProtectorId) backed up to $target ($($backup.TimeCreated.ToString('yyyy-MM-dd')))" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Recovery key $($k.KeyProtectorId): no backup event found" -ForegroundColor Yellow
            Write-Host "       Fix (Entra): BackupToAAD-BitLockerKeyProtector -MountPoint $($v.MountPoint) -KeyProtectorId '$($k.KeyProtectorId)'" -ForegroundColor DarkGray
            Write-Host "       Fix (AD):    Backup-BitLockerKeyProtector     -MountPoint $($v.MountPoint) -KeyProtectorId '$($k.KeyProtectorId)'" -ForegroundColor DarkGray
        }
    }
}
