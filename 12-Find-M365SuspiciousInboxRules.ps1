<#
.SYNOPSIS
    Hunts for typical Business-Email-Compromise (BEC) inbox rules in Exchange Online.

.DESCRIPTION
    After an account takeover, attackers almost always create inbox rules to
    hide replies from the victim or forward mail to themselves. This script flags:
      - Forward / redirect to EXTERNAL addresses
      - Rules that delete messages or mark them as read and move them away
      - Moves to rarely watched folders (RSS Feeds, RSS Subscriptions, Conversation History, Archive, Junk)
      - Suspicious rule names (".", "..", "a", single characters, only special chars)
      - Keyword filters like invoice, payment, bank, wire, Rechnung, Zahlung, IBAN ...
    Plus mailbox-level forwarding (ForwardingSmtpAddress).

    Read-only. Results go to console + CSV.

.EXAMPLE
    .\12-Find-M365SuspiciousInboxRules.ps1
.EXAMPLE
    .\12-Find-M365SuspiciousInboxRules.ps1 -Mailbox user@contoso.com -CsvPath C:\Temp\rules.csv

.NOTES
    Requires: ExchangeOnlineManagement. Large tenants: run per mailbox or overnight.
#>
[CmdletBinding()]
param(
    [string[]]$Mailbox,
    [string]$CsvPath = (Join-Path $PWD "M365-InboxRules_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"),
    [switch]$IncludeAllRules
)

$ErrorActionPreference = 'Stop'
Connect-ExchangeOnline -ShowBanner:$false

$acceptedDomains = (Get-AcceptedDomain).DomainName
$suspiciousFolders = 'RSS Feeds', 'RSS Subscriptions', 'RSS-Feeds', 'RSS-Abonnements', 'Conversation History',
    'Unterhaltungsverlauf', 'Archive', 'Archiv', 'Junk Email', 'Junk-E-Mail'
$keywords = 'invoice', 'payment', 'bank', 'wire', 'transfer', 'iban', 'rechnung', 'zahlung', 'überweisung',
    'password', 'passwort', 'hacked', 'phish', 'spam', 'security', 'helpdesk'

function Test-External([string]$Addr) {
    if (-not $Addr) { return $false }
    # Rule recipients look like: "Name" [SMTP:x@y.com]  or  x@y.com
    if ($Addr -match '[\w\.\-+]+@([\w\.\-]+)') { return ($Matches[1] -notin $acceptedDomains) }
    return $false
}

$mailboxes = if ($Mailbox) { $Mailbox | ForEach-Object { Get-EXOMailbox -Identity $_ -Properties ForwardingSmtpAddress } }
             else { Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox -Properties ForwardingSmtpAddress }

$out = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($mbx in $mailboxes) {
    $i++
    Write-Progress -Activity 'Scanning inbox rules' -Status $mbx.UserPrincipalName -PercentComplete (100 * $i / @($mailboxes).Count)

    if ($mbx.ForwardingSmtpAddress) {
        $out.Add([pscustomobject]@{
            Mailbox = $mbx.UserPrincipalName; RuleName = '(mailbox forwarding)'; Enabled = $true
            Risk = 'HIGH'; Reasons = "Mailbox forwards to $($mbx.ForwardingSmtpAddress)"; Actions = ''; Conditions = ''
        })
    }

    try { $rules = Get-InboxRule -Mailbox $mbx.UserPrincipalName -ErrorAction Stop }
    catch { Write-Warning "$($mbx.UserPrincipalName): $($_.Exception.Message)"; continue }

    foreach ($r in $rules) {
        $reasons = @(); $score = 0

        $targets = @($r.ForwardTo) + @($r.ForwardAsAttachmentTo) + @($r.RedirectTo) | Where-Object { $_ }
        $ext = $targets | Where-Object { Test-External $_ }
        if ($ext) { $reasons += "External forward/redirect: $($ext -join ', ')"; $score += 3 }
        elseif ($targets) { $reasons += 'Internal forward/redirect'; $score += 1 }

        if ($r.DeleteMessage -or $r.SoftDeleteMessage) { $reasons += 'Deletes messages'; $score += 2 }
        if ($r.MarkAsRead -and $r.MoveToFolder) { $reasons += 'Marks as read + moves'; $score += 1 }
        if ($r.MoveToFolder -and ($suspiciousFolders | Where-Object { $r.MoveToFolder -like "*$_*" })) {
            $reasons += "Moves to hidden folder: $($r.MoveToFolder)"; $score += 2
        }
        if ($r.Name -match '^[\W_]{1,5}$' -or $r.Name.Length -le 2) { $reasons += "Suspicious name '$($r.Name)'"; $score += 2 }

        $words = @($r.SubjectContainsWords) + @($r.SubjectOrBodyContainsWords) + @($r.BodyContainsWords) | Where-Object { $_ }
        $hit = $words | Where-Object { $w = $_; $keywords | Where-Object { $w -like "*$_*" } }
        if ($hit) { $reasons += "Keyword filter: $($hit -join ', ')"; $score += 1 }

        $risk = if ($score -ge 3) { 'HIGH' } elseif ($score -ge 2) { 'MEDIUM' } elseif ($score -ge 1) { 'LOW' } else { 'NONE' }
        if ($risk -ne 'NONE' -or $IncludeAllRules) {
            $out.Add([pscustomobject]@{
                Mailbox = $mbx.UserPrincipalName; RuleName = $r.Name; Enabled = $r.Enabled; Risk = $risk
                Reasons = ($reasons -join ' | '); Actions = ($r.Description -replace "`r?`n", ' '); Conditions = ($words -join ', ')
            })
        }
    }
}
Write-Progress -Activity 'Scanning inbox rules' -Completed

$sorted = $out | Sort-Object @{ e = { @{ HIGH = 0; MEDIUM = 1; LOW = 2; NONE = 3 }[$_.Risk] } }, Mailbox
$sorted | Format-Table Risk, Mailbox, RuleName, Enabled, Reasons -AutoSize -Wrap
$sorted | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

$high = @($sorted | Where-Object Risk -eq 'HIGH').Count
Write-Host "`n$(@($mailboxes).Count) mailboxes scanned - $high HIGH risk findings. CSV: $CsvPath" -ForegroundColor $(if ($high) { 'Red' } else { 'Green' })
if ($high) {
    Write-Host 'Next steps for HIGH findings: reset password, revoke sessions (Revoke-MgUserSignInSession), check sign-in logs, remove rule.' -ForegroundColor Yellow
}
Disconnect-ExchangeOnline -Confirm:$false
