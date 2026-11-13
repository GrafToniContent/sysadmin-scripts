<#
.SYNOPSIS
    Read-only hardening audit for Windows Server 2025 (works on 2019/2022 too).

.DESCRIPTION
    Checks 14 common hardening settings and prints PASS / WARN / FAIL:
      TLS 1.0 / 1.1 disabled, SMBv1 off, SMB signing, RDP with NLA, firewall profiles,
      Defender real-time protection, LSA protection (RunAsPPL), Credential Guard,
      WDigest, LLMNR, Print Spooler (on DCs), PowerShell 2.0 engine, last Windows update,
      local Guest account.
    Changes nothing. Run as administrator. Use -ComputerName for remote servers.

.EXAMPLE
    .\22-Get-ServerHardeningAudit.ps1
.EXAMPLE
    .\22-Get-ServerHardeningAudit.ps1 -ComputerName SRV01,SRV02 | Export-Csv audit.csv -NoTypeInformation
#>
[CmdletBinding()]
param([string[]]$ComputerName = $env:COMPUTERNAME)

$audit = {
    function Reg($path, $name) { (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name }
    $isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
    $schannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $tlsOff = {
        param($v)
        $e = Reg "$schannel\$v\Server" 'Enabled'
        # Server 2025 disables TLS 1.0/1.1 by default when no key exists
        ($e -eq 0) -or ($null -eq $e -and [Environment]::OSVersion.Version.Build -ge 26100)
    }
    $smb = Get-SmbServerConfiguration
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    $lastUpdate = (Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
    $spooler = Get-Service Spooler -ErrorAction SilentlyContinue
    $ps2 = Get-WindowsFeature PowerShell-V2 -ErrorAction SilentlyContinue

    @(
        ,@('TLS 1.0 disabled',            (& $tlsOff 'TLS 1.0'),                                  'FAIL')
        ,@('TLS 1.1 disabled',            (& $tlsOff 'TLS 1.1'),                                  'WARN')
        ,@('SMBv1 disabled',              (-not $smb.EnableSMB1Protocol),                         'FAIL')
        ,@('SMB signing required',        [bool]$smb.RequireSecuritySignature,                    'FAIL')
        ,@('RDP requires NLA',            ((Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication') -eq 1), 'FAIL')
        ,@('Firewall on (all profiles)',  (-not (Get-NetFirewallProfile | Where-Object Enabled -eq 'False')), 'FAIL')
        ,@('Defender real-time on',       ($mp -and $mp.RealTimeProtectionEnabled),               'WARN')
        ,@('LSA protection (RunAsPPL)',   ((Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL') -ge 1), 'WARN')
        ,@('Credential Guard running',    ($dg -and $dg.SecurityServicesRunning -contains 1),     'WARN')
        ,@('WDigest off',                 ((Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') -ne 1), 'FAIL')
        ,@('LLMNR disabled',              ((Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -eq 0), 'WARN')
        ,@('Print Spooler off (DC)',      ((-not $isDC) -or ($spooler.Status -ne 'Running')),     'FAIL')
        ,@('PowerShell 2.0 removed',      ((-not $ps2) -or (-not $ps2.Installed)),                'WARN')
        ,@('Updated in last 45 days',     ($lastUpdate -and $lastUpdate -gt (Get-Date).AddDays(-45)), 'FAIL')
        ,@('Guest account disabled',      (-not (Get-LocalUser | Where-Object { $_.SID -like '*-501' -and $_.Enabled })), 'FAIL')
    ) | ForEach-Object {
        [pscustomobject]@{ Computer = $env:COMPUTERNAME; Check = $_[0]; Status = if ($_[1]) { 'PASS' } else { $_[2] } }
    }
}

foreach ($pc in $ComputerName) {
    $res = if ($pc -eq $env:COMPUTERNAME) { & $audit } else { Invoke-Command -ComputerName $pc -ScriptBlock $audit }
    Write-Host "`n=== $pc ===" -ForegroundColor Cyan
    foreach ($r in $res) {
        Write-Host ("[{0}] {1}" -f $r.Status, $r.Check) -ForegroundColor (@{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red' }[$r.Status])
    }
    $f = @($res | Where-Object Status -eq 'FAIL').Count; $w = @($res | Where-Object Status -eq 'WARN').Count
    Write-Host ("{0}: {1} FAIL, {2} WARN" -f $pc, $f, $w) -ForegroundColor Cyan
    $res | Select-Object Computer, Check, Status
}
Write-Host "`nAudit first. Harden second. Apply the Microsoft Security Baseline / OSConfig for Server 2025 and test every change." -ForegroundColor DarkGray
