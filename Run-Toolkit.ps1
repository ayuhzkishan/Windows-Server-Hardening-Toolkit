#Requires -RunAsAdministrator
<#
.SYNOPSIS
    One-click runner: Hardens a Windows Server, validates compliance,
    and generates an HTML compliance report.

.DESCRIPTION
    Orchestrates the full Windows Server Hardening Toolkit pipeline:
      1. Runs Ansible playbook against target server(s)
      2. Executes Chef InSpec compliance validation
      3. Generates a timestamped HTML report in reports/

.PARAMETER InventoryFile
    Path to your Ansible inventory file. Default: ansible/inventory/hosts.yml

.PARAMETER Target
    WinRM target for InSpec (e.g., winrm://Admin:Pass@192.168.1.100).
    If omitted, InSpec runs in local mode.

.PARAMETER SkipHardening
    Skip the Ansible step and only run InSpec validation. Useful for auditing
    a server without making changes.

.PARAMETER SkipValidation
    Skip the InSpec step. Only runs Ansible hardening.

.PARAMETER Tags
    Only run specific Ansible tags (e.g., "network_hardening,audit_policy").

.EXAMPLE
    .\Run-Toolkit.ps1 -Target "winrm://Admin:Pass@192.168.56.10"
    .\Run-Toolkit.ps1 -SkipHardening -Target "winrm://Admin:Pass@192.168.56.10"
    .\Run-Toolkit.ps1 -Tags "network_hardening"

.NOTES
    Requirements: Ansible, Chef InSpec, Python 3.x must be in PATH
#>

[CmdletBinding()]
param(
    [string]$InventoryFile  = ".\ansible\inventory\hosts.yml",
    [string]$Target         = "",
    [switch]$SkipHardening  = $false,
    [switch]$SkipValidation = $false,
    [string]$Tags           = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Helpers ────────────────────────────────────────────────────
function Write-Banner {
    Write-Host @"

 ╔══════════════════════════════════════════════════════════╗
 ║      Windows Server Hardening Toolkit  v1.0.0           ║
 ║      CIS Benchmark Automation | 21 Controls             ║
 ╚══════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Write-Phase {
    param([string]$Phase, [string]$Description)
    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host " $Phase  $Description" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
}

function Test-CommandExists {
    param([string]$Command)
    return $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

function Get-Timestamp { return (Get-Date -Format "yyyyMMdd_HHmmss") }

# ── Preflight Checks ───────────────────────────────────────────
Write-Banner
Write-Phase "⚙️  PREFLIGHT" "Checking dependencies..."

$missingDeps = @()
if (-not $SkipHardening -and -not (Test-CommandExists "ansible-playbook")) {
    $missingDeps += "ansible-playbook (install: pip install ansible)"
}
if (-not $SkipValidation -and -not (Test-CommandExists "inspec")) {
    $missingDeps += "inspec (install: https://www.chef.io/downloads/tools/inspec)"
}

if ($missingDeps.Count -gt 0) {
    Write-Host "`n❌ Missing dependencies:" -ForegroundColor Red
    $missingDeps | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
    exit 1
}
Write-Host "  ✅ All dependencies found." -ForegroundColor Green

# Ensure reports dir exists
$reportsDir = ".\reports"
if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir | Out-Null }

$timestamp   = Get-Timestamp
$reportFile  = Join-Path $reportsDir "compliance_$timestamp.html"
$exitCode    = 0

# ══ PHASE 1: ANSIBLE HARDENING ════════════════════════════════
if (-not $SkipHardening) {
    Write-Phase "🔒 PHASE 1" "Running Ansible Hardening Playbook"

    if (-not (Test-Path $InventoryFile)) {
        Write-Host "❌ Inventory file not found: $InventoryFile" -ForegroundColor Red
        Write-Host "   Edit ansible/inventory/hosts.yml with your server details." -ForegroundColor Gray
        exit 1
    }

    $ansibleArgs = @(
        "ansible\site.yml",
        "-i", $InventoryFile,
        "-v"
    )
    if ($Tags -ne "") { $ansibleArgs += @("--tags", $Tags) }

    Write-Host "  Running: ansible-playbook $($ansibleArgs -join ' ')" -ForegroundColor Gray
    & ansible-playbook @ansibleArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n❌ Ansible playbook failed (exit code $LASTEXITCODE)." -ForegroundColor Red
        $exitCode = $LASTEXITCODE
    } else {
        Write-Host "`n  ✅ Ansible hardening complete." -ForegroundColor Green
    }
} else {
    Write-Host "`n⏭️  Skipping Ansible hardening (--SkipHardening flag set)." -ForegroundColor DarkGray
}

# ══ PHASE 2: INSPEC VALIDATION ═══════════════════════════════
if (-not $SkipValidation) {
    Write-Phase "🔍 PHASE 2" "Running InSpec Compliance Validation"

    $inspecArgs = @(
        "exec", "inspec\",
        "--reporter", "html2:$reportFile", "cli"
    )
    if ($Target -ne "") {
        $inspecArgs += @("-t", $Target)
    }

    Write-Host "  Running: inspec $($inspecArgs -join ' ')" -ForegroundColor Gray
    Write-Host "  Report will be saved to: $reportFile" -ForegroundColor Gray

    & inspec @inspecArgs
    $inspecExit = $LASTEXITCODE

    switch ($inspecExit) {
        0 { Write-Host "`n  ✅ All controls PASSED." -ForegroundColor Green }
        100 { Write-Host "`n  ⚠️  Some controls FAILED. Review the report." -ForegroundColor Yellow; $exitCode = 100 }
        101 { Write-Host "`n  ⚠️  Some controls SKIPPED." -ForegroundColor Yellow }
        default { Write-Host "`n  ❌ InSpec error (exit code $inspecExit)." -ForegroundColor Red; $exitCode = $inspecExit }
    }
} else {
    Write-Host "`n⏭️  Skipping InSpec validation (--SkipValidation flag set)." -ForegroundColor DarkGray
}

# ══ SUMMARY ══════════════════════════════════════════════════
Write-Phase "📊 SUMMARY" "Run Complete"
Write-Host "  Timestamp  : $timestamp"
if (-not $SkipValidation -and (Test-Path $reportFile)) {
    Write-Host "  Report     : $reportFile" -ForegroundColor Cyan
    Write-Host "  Opening report in browser..." -ForegroundColor Gray
    Start-Process $reportFile
}
Write-Host "  Exit Code  : $exitCode"

if ($exitCode -eq 0) {
    Write-Host "`n  ✅ Toolkit run successful." -ForegroundColor Green
} else {
    Write-Host "`n  ⚠️  Toolkit completed with warnings. See report." -ForegroundColor Yellow
}

exit $exitCode
