#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs Sysmon with the SwiftOnSecurity high-fidelity configuration.

.DESCRIPTION
    Downloads Sysmon from Microsoft Sysinternals and the SwiftOnSecurity
    sysmon-config from GitHub. Installs Sysmon as a Windows service, or
    updates the configuration if it is already installed. Fully idempotent.

.PARAMETER InstallPath
    Directory to install Sysmon into. Default: C:\Windows\Sysmon

.PARAMETER SysmonUrl
    Override the Sysmon download URL.

.PARAMETER ConfigUrl
    Override the sysmon-config download URL.

.EXAMPLE
    .\Install-Sysmon.ps1
    .\Install-Sysmon.ps1 -InstallPath "D:\Tools\Sysmon"

.NOTES
    CIS Controls Supported: Supplementary telemetry (not a numbered control)
    MITRE ATT&CK: Supports detection of T1059, T1218, T1003, T1078 and more
#>

[CmdletBinding()]
param(
    [string]$InstallPath = "C:\Windows\Sysmon",
    [string]$SysmonUrl  = "https://download.sysinternals.com/files/Sysmon.zip",
    [string]$ConfigUrl  = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "`n[SYSMON] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "  ✅ $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  ⚠️  $Message" -ForegroundColor Yellow
}

# ── Step 1: Create install directory ──────────────────────────
Write-Step "Ensuring install directory: $InstallPath"
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Write-Success "Created directory."
} else {
    Write-Success "Directory already exists."
}

# ── Step 2: Download Sysmon ────────────────────────────────────
Write-Step "Downloading Sysmon from Sysinternals..."
$sysmonZip = Join-Path $InstallPath "Sysmon.zip"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $sysmonZip -UseBasicParsing
    Write-Success "Downloaded Sysmon.zip"
} catch {
    Write-Error "Failed to download Sysmon: $_"
    exit 1
}

# ── Step 3: Extract Sysmon ─────────────────────────────────────
Write-Step "Extracting Sysmon..."
Expand-Archive -Path $sysmonZip -DestinationPath $InstallPath -Force
Write-Success "Extracted Sysmon to $InstallPath"

# ── Step 4: Download SwiftOnSecurity config ────────────────────
Write-Step "Downloading SwiftOnSecurity sysmon-config..."
$configPath = Join-Path $InstallPath "sysmonconfig.xml"
try {
    Invoke-WebRequest -Uri $ConfigUrl -OutFile $configPath -UseBasicParsing
    Write-Success "Downloaded sysmonconfig.xml"
} catch {
    Write-Error "Failed to download sysmon-config: $_"
    exit 1
}

# ── Step 5: Install or Update Sysmon ──────────────────────────
$sysmonExe = Join-Path $InstallPath "Sysmon64.exe"
$sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

if ($null -eq $sysmonService) {
    Write-Step "Installing Sysmon for the first time..."
    & $sysmonExe -accepteula -i $configPath | Out-Null
    Write-Success "Sysmon installed successfully."
} else {
    Write-Step "Sysmon already installed — updating configuration..."
    & $sysmonExe -c $configPath | Out-Null
    Write-Success "Sysmon configuration updated."
}

# ── Step 6: Verify service is running ─────────────────────────
Write-Step "Verifying Sysmon service state..."
$service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Success "Sysmon64 service is RUNNING."
} else {
    Write-Warn "Sysmon64 service is not running. Attempting to start..."
    Start-Service -Name "Sysmon64"
    Write-Success "Sysmon64 started."
}

Write-Host "`n✅ Sysmon deployment complete." -ForegroundColor Green
Write-Host "   Logs are visible in: Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational" -ForegroundColor Gray
