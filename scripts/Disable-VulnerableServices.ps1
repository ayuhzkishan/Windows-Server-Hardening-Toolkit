#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Disables known-vulnerable Windows services per CIS Benchmark Section 5.

.DESCRIPTION
    Stops and disables high-risk Windows services. Covers Print Spooler
    (PrintNightmare), Remote Registry, and Xbox services. Fully idempotent.

.PARAMETER SkipWinRM
    Skip disabling WinRM (recommended when managing via Ansible/WinRM).

.EXAMPLE
    .\Disable-VulnerableServices.ps1
    .\Disable-VulnerableServices.ps1 -SkipWinRM:$false

.NOTES
    CIS Controls: 5.29 (Print Spooler), 5.30 (Remote Registry), 5.41 (Xbox)
    CVEs Mitigated: CVE-2021-1675, CVE-2021-34527 (PrintNightmare)
#>

[CmdletBinding()]
param(
    [switch]$SkipWinRM = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Disable-Service {
    param(
        [string]$ServiceName,
        [string]$CisControl,
        [string]$Reason
    )

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "  ⏭️  [$CisControl] $ServiceName - Not found (skip)" -ForegroundColor DarkGray
        return
    }

    try {
        if ($svc.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force
        }
        Set-Service -Name $ServiceName -StartupType Disabled
        Write-Host "  ✅ [$CisControl] $ServiceName disabled — $Reason" -ForegroundColor Green
    } catch {
        Write-Warning "  ⚠️  Failed to disable $ServiceName : $_"
    }
}

Write-Host "`n🔒 Disabling Vulnerable Windows Services (CIS Section 5)..." -ForegroundColor Cyan
Write-Host "   Reference: CIS Windows Server 2019 Benchmark v2.0.0 - Section 5" -ForegroundColor Gray

# ── CIS 5.29 — Print Spooler (PrintNightmare) ──────────────────
Write-Host "`n[CIS 5.29] Print Spooler" -ForegroundColor Yellow
Disable-Service -ServiceName "Spooler" `
    -CisControl "5.29" `
    -Reason "Mitigates PrintNightmare (CVE-2021-1675 / CVE-2021-34527)"

# ── CIS 5.30 — Remote Registry ─────────────────────────────────
Write-Host "`n[CIS 5.30] Remote Registry" -ForegroundColor Yellow
Disable-Service -ServiceName "RemoteRegistry" `
    -CisControl "5.30" `
    -Reason "Prevents remote registry reads/writes (lateral movement vector)"

# ── CIS 5.41 — Xbox Services ───────────────────────────────────
Write-Host "`n[CIS 5.41] Xbox Services" -ForegroundColor Yellow
$xboxServices = @(
    @{ Name = "XboxGipSvc";    Label = "Xbox Accessory Management" },
    @{ Name = "XblAuthManager"; Label = "Xbox Live Auth Manager"   },
    @{ Name = "XblGameSave";   Label = "Xbox Live Game Save"       },
    @{ Name = "XboxNetApiSvc"; Label = "Xbox Live Networking"      }
)
foreach ($svc in $xboxServices) {
    Disable-Service -ServiceName $svc.Name `
        -CisControl "5.41" `
        -Reason "No purpose on server OS — reduces attack surface"
}

# ── SMBv1 — EternalBlue / WannaCry / NotPetya ─────────────────
Write-Host "`n[BONUS] SMBv1 Protocol" -ForegroundColor Yellow
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
if ($smb1 -and $smb1.State -eq "Enabled") {
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart | Out-Null
    Write-Host "  ✅ [BONUS] SMBv1 disabled — Mitigates EternalBlue (CVE-2017-0144)" -ForegroundColor Green
} else {
    Write-Host "  ✅ [BONUS] SMBv1 already disabled." -ForegroundColor Green
}

# ── Optional: WinRM (skip by default) ─────────────────────────
if (-not $SkipWinRM) {
    Write-Host "`n[CIS 5.39] WinRM (Windows Remote Management)" -ForegroundColor Yellow
    Write-Host "  ⚠️  WARNING: Disabling WinRM will break Ansible connectivity!" -ForegroundColor Red
    Disable-Service -ServiceName "WinRM" `
        -CisControl "5.39" `
        -Reason "Remote management interface not required"
} else {
    Write-Host "`n[CIS 5.39] WinRM — SKIPPED (use -SkipWinRM:`$false to apply)" -ForegroundColor DarkGray
}

Write-Host "`n✅ Vulnerable service hardening complete." -ForegroundColor Green
Write-Host "   Verify with: Get-Service Spooler, RemoteRegistry | Select Name, Status, StartType" -ForegroundColor Gray
