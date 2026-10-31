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
