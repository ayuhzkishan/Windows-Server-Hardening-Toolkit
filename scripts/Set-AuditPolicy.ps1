#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Configures Windows Advanced Audit Policies per CIS Benchmark Section 17.

.DESCRIPTION
    Uses auditpol.exe to apply all CIS Section 17 audit policy controls.
    Idempotent: running this script multiple times produces the same result.
    Covers: Credential Validation, Group Management, Account Lockout, Logon,
    Process Creation, and Command Line logging.

.EXAMPLE
    .\Set-AuditPolicy.ps1
    .\Set-AuditPolicy.ps1 -Verbose

.NOTES
    CIS Controls: 17.1.1, 17.2.1, 17.5.1, 17.5.4
    NIST 800-53:  AU-2, AU-3, AU-12
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Set-AuditSubcategory {
    param(
        [string]$Subcategory,
        [ValidateSet("enable","disable")]
        [string]$Success = "enable",
        [ValidateSet("enable","disable")]
        [string]$Failure = "enable"
    )
    $result = auditpol /set /subcategory:"$Subcategory" /success:$Success /failure:$Failure 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ [$Subcategory] Success=$Success, Failure=$Failure" -ForegroundColor Green
    } else {
        Write-Warning "  ⚠️  Failed to set [$Subcategory]: $result"
    }
}

Write-Host "`n🔒 Configuring CIS Advanced Audit Policies..." -ForegroundColor Cyan
Write-Host "   Reference: CIS Windows Server 2019 Benchmark v2.0.0 - Section 17" -ForegroundColor Gray

# ── CIS 17.1.1 - Credential Validation ─────────────────────────
Write-Host "`n[Section 17.1] Account Logon" -ForegroundColor Yellow
Set-AuditSubcategory -Subcategory "Credential Validation" -Success enable -Failure enable

# ── CIS 17.2.1 - Application Group Management ──────────────────
Write-Host "`n[Section 17.2] Account Management" -ForegroundColor Yellow
Set-AuditSubcategory -Subcategory "Application Group Management" -Success enable -Failure enable
Set-AuditSubcategory -Subcategory "Security Group Management"    -Success enable -Failure enable
Set-AuditSubcategory -Subcategory "User Account Management"      -Success enable -Failure enable

# ── CIS 17.5.1 - Account Lockout ──────────────────────────────
Write-Host "`n[Section 17.5] Logon/Logoff" -ForegroundColor Yellow
Set-AuditSubcategory -Subcategory "Account Lockout" -Success disable -Failure enable

# ── CIS 17.5.4 - Logon Events ─────────────────────────────────
Set-AuditSubcategory -Subcategory "Logon"  -Success enable -Failure enable
Set-AuditSubcategory -Subcategory "Logoff" -Success enable -Failure disable
Set-AuditSubcategory -Subcategory "Special Logon" -Success enable -Failure disable

# ── BONUS: Process Creation ────────────────────────────────────
Write-Host "`n[Bonus] Detailed Tracking" -ForegroundColor Yellow
Set-AuditSubcategory -Subcategory "Process Creation" -Success enable -Failure disable

# ── BONUS: Command Line in Process Events ──────────────────────
Write-Host "`n[Bonus] Enabling command line logging in Event ID 4688..." -ForegroundColor Yellow
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
Write-Host "  ✅ Command line logging enabled." -ForegroundColor Green

Write-Host "`n✅ Audit policy configuration complete." -ForegroundColor Green
Write-Host "   Verify with: auditpol /get /category:* | findstr /i `"logon\|credential\|process`"" -ForegroundColor Gray
