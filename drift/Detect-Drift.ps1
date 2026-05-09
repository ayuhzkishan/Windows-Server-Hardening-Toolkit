#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Continuously monitors for security configuration drift and auto-remediates.

.DESCRIPTION
    Runs Chef InSpec compliance checks against the local machine (or a remote
    target). If any controls fail, it logs a warning to the Windows Event Log
    and optionally re-triggers the Ansible playbook to restore compliance.

    Designed to be registered as a Windows Scheduled Task that runs hourly.

.PARAMETER InSpecProfilePath
    Path to the InSpec profile directory. Default: parent directory's inspec\

.PARAMETER InventoryFile
    Ansible inventory file for auto-remediation. Default: ansible/inventory/hosts.yml

.PARAMETER Target
    WinRM target for InSpec. Runs in local mode if omitted.

.PARAMETER AutoRemediate
    If set, triggers Ansible to restore compliance when drift is detected.
    DEFAULT: off (log-only mode for safety).

.PARAMETER Register
    Register this script as a Windows Scheduled Task (runs hourly).

.PARAMETER IntervalMinutes
    How often to run when registered as a Scheduled Task. Default: 60.

.PARAMETER Unregister
    Remove the Scheduled Task created by -Register.

.EXAMPLE
    # Run once (log-only mode)
    .\Detect-Drift.ps1

    # Run with auto-remediation
    .\Detect-Drift.ps1 -AutoRemediate

    # Register as hourly scheduled task
    .\Detect-Drift.ps1 -Register -IntervalMinutes 60

    # Unregister the scheduled task
    .\Detect-Drift.ps1 -Unregister

.NOTES
    Event Log Source: WindowsHardeningToolkit
    Event IDs:
      1000 - Drift check started
      1001 - All controls passing (no drift)
      1002 - Drift DETECTED (controls failing)
      1003 - Auto-remediation triggered
      1004 - Auto-remediation completed
#>

[CmdletBinding()]
param(
    [string]$InSpecProfilePath = "",
    [string]$InventoryFile     = "",
    [string]$Target            = "",
    [switch]$AutoRemediate     = $false,
    [switch]$Register          = $false,
    [int]$IntervalMinutes      = 60,
    [switch]$Unregister        = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Constants ──────────────────────────────────────────────────
$EventSource   = "WindowsHardeningToolkit"
$EventLog      = "Application"
$TaskName      = "CIS-Hardening-DriftDetection"

# Resolve paths relative to this script's location
$scriptRoot    = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot   = Split-Path -Parent $scriptRoot

if ($InSpecProfilePath -eq "") {
    $InSpecProfilePath = Join-Path $projectRoot "inspec"
}
if ($InventoryFile -eq "") {
    $InventoryFile = Join-Path $projectRoot "ansible\inventory\hosts.yml"
}

# ── Register as Scheduled Task ─────────────────────────────────
if ($Unregister) {
    Write-Host "Removing scheduled task '$TaskName'..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "✅ Scheduled task removed." -ForegroundColor Green
    exit 0
}

if ($Register) {
    Write-Host "Registering '$TaskName' as a scheduled task (every $IntervalMinutes min)..." -ForegroundColor Cyan
    $psExe   = (Get-Command pwsh -ErrorAction SilentlyContinue)?.Source
    if (-not $psExe) { $psExe = "powershell.exe" }

    $action  = New-ScheduledTaskAction -Execute $psExe `
        -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -Once -At (Get-Date)
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Settings $settings -Principal $principal -Force | Out-Null

    Write-Host "✅ Scheduled task '$TaskName' registered (runs every $IntervalMinutes minutes)." -ForegroundColor Green
    exit 0
}

# ── Ensure Event Log source exists ─────────────────────────────
if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    New-EventLog -LogName $EventLog -Source $EventSource
}

function Write-EventEntry {
    param([int]$EventId, [string]$Message, [string]$EntryType = "Information")
    Write-EventLog -LogName $EventLog -Source $EventSource `
        -EventId $EventId -EntryType $EntryType -Message $Message
}

# ── Helpers ────────────────────────────────────────────────────
function Write-Status {
    param([string]$Msg, [string]$Color = "White")
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host "[$ts] $Msg" -ForegroundColor $Color
}

# ══ MAIN DRIFT CHECK ══════════════════════════════════════════
Write-Status "🔍 Starting CIS compliance drift check..." Cyan
Write-EventEntry -EventId 1000 -Message "CIS Hardening Toolkit: Drift check started at $(Get-Date -Format 'u')."

# ── Run InSpec ─────────────────────────────────────────────────
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$reportDir  = Join-Path $projectRoot "reports"
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir | Out-Null }
$reportFile = Join-Path $reportDir "drift_$timestamp.json"

$inspecArgs = @("exec", $InSpecProfilePath, "--reporter", "json:$reportFile", "cli")
if ($Target -ne "") { $inspecArgs += @("-t", $Target) }

Write-Status "  Running: inspec $($inspecArgs -join ' ')" Gray
& inspec @inspecArgs 2>&1 | Out-Null
$inspecExit = $LASTEXITCODE

# ── Parse Results ──────────────────────────────────────────────
$driftDetected   = $false
$failedControls  = @()
$passedCount     = 0
$failedCount     = 0

if (Test-Path $reportFile) {
    $report = Get-Content $reportFile | ConvertFrom-Json
    foreach ($profile in $report.profiles) {
        foreach ($control in $profile.controls) {
            $failed = $control.results | Where-Object { $_.status -eq "failed" }
            if ($failed) {
                $driftDetected = $true
                $failedControls += $control.id
                $failedCount++
            } else {
                $passedCount++
            }
        }
    }
}

# ── Report Results ─────────────────────────────────────────────
$total   = $passedCount + $failedCount
$pct     = if ($total -gt 0) { [math]::Round(($passedCount / $total) * 100, 1) } else { 0 }

if (-not $driftDetected) {
    Write-Status "✅ No drift detected. All $total controls passing ($pct% compliance)." Green
    Write-EventEntry -EventId 1001 `
        -Message "CIS Hardening Toolkit: No drift detected. $total/$total controls passing."
} else {
    $failedList = $failedControls -join ", "
    Write-Status "⚠️  DRIFT DETECTED: $failedCount/$total controls failing ($pct% compliance)." Red
    Write-Status "   Failed controls: $failedList" Yellow

    $eventMsg = @"
CIS Hardening Toolkit: CONFIGURATION DRIFT DETECTED at $(Get-Date -Format 'u').
Compliance: $passedCount/$total controls passing ($pct%).
Failed Controls: $failedList
Report: $reportFile
"@
    Write-EventEntry -EventId 1002 -Message $eventMsg -EntryType "Warning"

    # ── Auto-Remediate ─────────────────────────────────────────
    if ($AutoRemediate) {
        Write-Status "🔧 Auto-remediation triggered. Running Ansible playbook..." Yellow
        Write-EventEntry -EventId 1003 `
            -Message "CIS Hardening Toolkit: Auto-remediation triggered for controls: $failedList"

        $ansibleArgs = @("ansible\site.yml", "-i", $InventoryFile)
        & ansible-playbook @ansibleArgs | Out-Null

        if ($LASTEXITCODE -eq 0) {
            Write-Status "✅ Auto-remediation complete." Green
            Write-EventEntry -EventId 1004 `
                -Message "CIS Hardening Toolkit: Auto-remediation completed successfully."
        } else {
            Write-Status "❌ Auto-remediation failed (exit $LASTEXITCODE)." Red
        }
    } else {
        Write-Status "   Auto-remediation is OFF. Run with -AutoRemediate to enable." Gray
        Write-Status "   Or manually run: .\Run-Toolkit.ps1 -SkipValidation" Gray
    }
}

Write-Status "Report saved to: $reportFile" Gray
exit $(if ($driftDetected) { 1 } else { 0 })
