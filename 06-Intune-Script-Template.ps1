<#
.SYNOPSIS
    Template for Intune platform scripts (Devices > Scripts and remediations > Platform scripts).

.DESCRIPTION
    Avoids the three classic traps of Intune PowerShell scripts:

    1. 32-bit host: "Run script in 64-bit PowerShell host" defaults to No. In a 32-bit host,
       writes to HKLM:\SOFTWARE are redirected to WOW6432Node and System32 maps to SysWOW64.
       This template relaunches itself in 64-bit PowerShell automatically.
    2. No real logging: Intune only reports success/failure. Everything is written to a
       transcript in C:\ProgramData so you can see what actually happened.
    3. Wrong context / signature: set these in the Intune script settings:
         Run this script using the logged on credentials: No   (runs as SYSTEM)
         Enforce script signature check:                  No   (or sign the script)
         Run script in 64-bit PowerShell host:            Yes

    Remember: platform scripts run ONCE per device (plus up to 3 retries on failure).
    For anything that must be checked or fixed regularly, use Remediations instead.

    Exit code 0 = success in Intune, anything else = failure.

.NOTES
    Graf Toni Content - "Automate it once. Never do it again."
    Keep the script below 200 KB. Never put passwords or personal data in Intune scripts.
#>

# --- 1. Relaunch in 64-bit PowerShell if Intune started us in 32-bit --------------------
if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') {
    $ps64 = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    exit $LASTEXITCODE
}

# --- 2. Logging --------------------------------------------------------------------------
$logFile = Join-Path $env:ProgramData 'GrafToni\Intune\intune-script.log'
New-Item -Path (Split-Path $logFile) -ItemType Directory -Force | Out-Null
Start-Transcript -Path $logFile -Append | Out-Null

Write-Output "Start: $(Get-Date -Format s) | User: $(whoami) | 64-bit: $([Environment]::Is64BitProcess)"

$ErrorActionPreference = 'Stop'   # make every error land in catch

try {
    # --- 3. YOUR CODE GOES HERE ------------------------------------------------------------
    # Example: write a marker to the 64-bit registry
    $key = 'HKLM:\SOFTWARE\GrafToni'
    if (-not (Test-Path $key)) { New-Item -Path $key | Out-Null }
    Set-ItemProperty -Path $key -Name 'Configured' -Value 1 -Type DWord
    Write-Output "Registry marker set in $key"
    # ------------------------------------------------------------------------------------

    Write-Output 'Done.'
    $exitCode = 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    $exitCode = 1
}
finally {
    Stop-Transcript | Out-Null
}

exit $exitCode
