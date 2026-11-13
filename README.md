# 👑 Graf Toni Content – Sysadmin Automation Scripts

> **Automate it once. Never do it again.**

Free PowerShell scripts from the **Graf Toni Content** videos – one sysadmin automation every week.
Follow along on TikTok [@graf_toni_content](https://www.tiktok.com/@graf_toni_content), Instagram [@graf.toni.content](https://www.instagram.com/graf.toni.content) and YouTube.

| # | Script | What it does | Requires |
|---|--------|--------------|----------|
| 01 | [`01-New-BulkADUsers.ps1`](01-New-BulkADUsers.ps1) | Creates AD users in bulk from a CSV, skips duplicates, random initial passwords | ActiveDirectory module |
| 02 | [`02-Disable-StaleADUsers.ps1`](02-Disable-StaleADUsers.ps1) | Finds users without logon for X days, exports a report, disables them | ActiveDirectory module |
| 03 | [`03-Export-EntraUsers-Graph.ps1`](03-Export-EntraUsers-Graph.ps1) | Exports all Entra ID users with Microsoft Graph (AzureAD replacement) | Microsoft.Graph.Users |
| 04 | [`04-Send-DiskAlert.ps1`](04-Send-DiskAlert.ps1) | Emails you before a server disk fills up – incl. unreachable servers | SMTP relay |
| 05 | [`05-Restart-ServiceSelfHeal.ps1`](05-Restart-ServiceSelfHeal.ps1) | Restarts stopped services and notifies the team | – |
| 06 | [`06-Intune-Script-Template.ps1`](06-Intune-Script-Template.ps1) | Template for Intune platform scripts: 64-bit relaunch, logging, exit codes | Intune |
| 07 | [`07-Get-HardeningAudit.ps1`](07-Get-HardeningAudit.ps1) | Read-only Windows 11 hardening audit (14 checks, optional HTML report) | Admin rights |
| 08 | [`08-Get-M365ServiceHealth.ps1`](08-Get-M365ServiceHealth.ps1) | Microsoft 365 service status, open incidents, watch mode, Teams alerts, monitoring exit codes | Microsoft.Graph |
| 09 | [`09-Get-M365SecurityAudit.ps1`](09-Get-M365SecurityAudit.ps1) | Read-only M365 / Entra ID security audit with HTML report (CA, MFA, admins, consent, Exchange) | Microsoft.Graph, ExchangeOnlineManagement |
| 10 | [`10-Set-M365Hardening.ps1`](10-Set-M365Hardening.ps1) | M365 baseline hardening – opt-in, -WhatIf, CA policies report-only, break-glass required | Microsoft.Graph, ExchangeOnlineManagement |
| 11 | [`11-Get-LocalAdminReport.ps1`](11-Get-LocalAdminReport.ps1) | Lists local administrators on many Windows PCs and flags unexpected members | PowerShell Remoting |
| 12 | [`12-Find-M365SuspiciousInboxRules.ps1`](12-Find-M365SuspiciousInboxRules.ps1) | Hunts BEC inbox rules: external forwarding, hidden folders, suspicious names | ExchangeOnlineManagement |
| 13 | [`13-Test-SmbHardening.ps1`](13-Test-SmbHardening.ps1) | SMB security check for Server 2025: SMBv1, signing, encryption, guest logons, NTLM | Admin rights |
| 14 | [`14-Get-EntraAppCredentialExpiry.ps1`](14-Get-EntraAppCredentialExpiry.ps1) | Expiring app registration secrets and certificates, monitoring exit codes | Microsoft.Graph.Applications |
| 15 | [`15-Set-AsrRules.ps1`](15-Set-AsrRules.ps1) | Shows and enables Defender Attack Surface Reduction rules (audit / block, -WhatIf) | Defender, admin rights |
| 16 | [`16-Get-EntraMfaMethodReport.ps1`](16-Get-EntraMfaMethodReport.ps1) | MFA strength per user: phishing-resistant, standard, SMS-only, none | Microsoft.Graph, Entra ID P1 |
| 17 | [`17-Find-NtlmUsage.ps1`](17-Find-NtlmUsage.ps1) | Finds NTLM and NTLMv1 logons on domain controllers (event 4624) | ActiveDirectory module |
| 18 | [`18-Test-BitLockerKeyBackup.ps1`](18-Test-BitLockerKeyBackup.ps1) | Checks BitLocker status and whether recovery keys are backed up to Entra ID / AD | Admin rights |
| 19 | [`19-Get-M365SharingSettings.ps1`](19-Get-M365SharingSettings.ps1) | Rates SharePoint / OneDrive external sharing settings | Microsoft.Graph |
| 20 | [`20-Find-KerberoastableAccounts.ps1`](20-Find-KerberoastableAccounts.ps1) | Service accounts with SPNs: privileged, old passwords, RC4 – Kerberoasting risk | ActiveDirectory module |
| 21 | [`21-Get-WindowsLapsStatus.ps1`](21-Get-WindowsLapsStatus.ps1) | Which computers have no (or only legacy) LAPS password | ActiveDirectory module |
| 22 | [`22-Get-ServerHardeningAudit.ps1`](22-Get-ServerHardeningAudit.ps1) | Read-only Windows Server 2025 hardening audit (15 checks) | Admin rights |
| 23 | [`23-Get-EntraRoleAssignmentChanges.ps1`](23-Get-EntraRoleAssignmentChanges.ps1) | Who got an admin role in Entra ID in the last 30 days, by whom, from which IP | Microsoft.Graph |

## Quick start

```powershell
# every script has built-in help
Get-Help .\01-New-BulkADUsers.ps1 -Full

# dry run first where supported
.\02-Disable-StaleADUsers.ps1 -Days 90 -WhatIf
```

If scripts are blocked, allow local scripts for your user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
Unblock-File .\*.ps1
```

## ⚠️ Before you run anything

- **Test in a lab first.** These scripts change real accounts and services.
- Read the script – you should understand what runs in your environment.
- Scripts 01 and 02 support `-WhatIf`. Use it.
- The password file from script 01 contains initial passwords: hand it over securely and delete it.

## Contributing

Found a bug or have an idea for the next automation? Open an issue – the best ideas become videos.

## License

[MIT](LICENSE) – use it, change it, share it. No warranty.
