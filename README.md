<div align="center">

# 🛡️ Windows Server Hardening Toolkit

**Automated, Idempotent, CIS-Compliant Windows Server Hardening**

[![CIS Benchmark](https://img.shields.io/badge/CIS-Windows%20Server%202019%20v2.0.0-blue?style=for-the-badge)](https://www.cisecurity.org/benchmark/microsoft_windows_server)
[![Ansible](https://img.shields.io/badge/Ansible-2.15+-EE0000?style=for-the-badge&logo=ansible)](https://www.ansible.com/)
[![InSpec](https://img.shields.io/badge/Chef%20InSpec-6.x-FF6400?style=for-the-badge)](https://www.chef.io/products/chef-inspec)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.x-5391FE?style=for-the-badge&logo=powershell)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

*A production-grade security toolkit that treats hardening as Infrastructure as Code. Implements 21 CIS Benchmark controls across Account Policies, Network Security, Service Management, and Audit Policy — with automated validation, HTML compliance reporting, and drift detection.*

</div>

---

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [CIS Controls Covered](#cis-controls-covered)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Running the Full Hardening Suite](#running-the-full-hardening-suite)
  - [Running Validation Only](#running-validation-only)
  - [Enabling Drift Detection](#enabling-drift-detection)
- [Configuration](#configuration)
- [Compliance Reports](#compliance-reports)
- [Lab Environment (Vagrant)](#lab-environment-vagrant)
- [Contributing](#contributing)

---

## Architecture Overview

This toolkit is built using a three-layer architecture mirroring enterprise security engineering practices:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ORCHESTRATION LAYER                          │
│              Ansible Playbooks (site.yml + Roles)                   │
│         Agentless, idempotent, scales to 1 or 1,000 servers        │
└────────────────────────────┬────────────────────────────────────────┘
                             │ calls
┌────────────────────────────▼────────────────────────────────────────┐
│                       IMPLEMENTATION LAYER                          │
│         PowerShell (win_regedit, win_security_policy modules)       │
│           Direct surgery on Windows Registry, WMI, Services         │
└────────────────────────────┬────────────────────────────────────────┘
                             │ validates
┌────────────────────────────▼────────────────────────────────────────┐
│                        VALIDATION LAYER                             │
│              Chef InSpec Compliance-as-Code Profiles                │
│          Audits every control and generates an HTML report          │
└─────────────────────────────────────────────────────────────────────┘
```

**Plus:**
- 🔍 **Drift Detection** — Hourly checks that security settings haven't been reverted
- 📊 **Sysmon Telemetry** — SwiftOnSecurity config deployed for log collection
- 🏗️ **Lab Environment** — Vagrant-based Windows Server test lab

---

## CIS Controls Covered

This toolkit implements **21 controls** from the CIS Microsoft Windows Server 2019 Benchmark v2.0.0:

| Category | Controls | CIS Section |
|----------|----------|-------------|
| Account Policies | 7 | Section 1 |
| Network Security | 6 | Section 18 |
| Service Management | 4 | Section 5 |
| Audit Policy | 4 | Section 17 |

> 📄 See [`docs/cis_control_mapping.md`](docs/cis_control_mapping.md) for full traceability →  
> Each control maps to its specific Ansible task and InSpec validation test.

### Highlights
- 🔐 **LSA Protection (RunAsPPL)** — Prevents credential dumping via tools like Mimikatz
- 🚫 **LLMNR/NetBIOS Disabled** — Eliminates Responder poisoning attack surface
- 💀 **WDigest Disabled** — Removes plaintext credential storage from LSASS
- 🖨️ **Print Spooler Disabled** — Mitigates PrintNightmare (CVE-2021-1675)
- 📝 **Advanced Audit Policies** — Full logon, lockout, and credential event logging

---

## Prerequisites

### Control Machine (Where you run Ansible)
- Python 3.10+
- Ansible 2.15+ with `ansible.windows` collection
- Chef InSpec 6.x

```bash
pip install ansible
ansible-galaxy collection install ansible.windows
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec
```

### Target Windows Server
- Windows Server 2016, 2019, or 2022
- WinRM enabled (for Ansible connectivity)
- PowerShell 5.1+ (built-in) or PowerShell 7+

### Enable WinRM on the target (run as Administrator):
```powershell
winrm quickconfig -q
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
```

---

## Project Structure

```
Windows-Server-Hardening-Toolkit/
├── ansible/
│   ├── roles/
│   │   ├── account_hardening/     # CIS Section 1 - Password & lockout policy
│   │   ├── network_hardening/     # CIS Section 18 - LLMNR, WDigest, LSA, SMB
│   │   ├── service_hardening/     # CIS Section 5 - Print Spooler, Remote Registry
│   │   ├── audit_policy/          # CIS Section 17 - Advanced Audit Policies
│   │   └── sysmon_deployment/     # Sysmon + SwiftOnSecurity config
│   ├── inventory/
│   │   └── hosts.yml
│   ├── group_vars/
│   │   └── all.yml                # Toggle individual control categories
│   └── site.yml                   # Main playbook entry point
├── inspec/
│   ├── controls/
│   │   ├── account_controls.rb    # Validates account policy settings
│   │   ├── network_controls.rb    # Validates registry-level network settings
│   │   ├── service_controls.rb    # Validates service states
│   │   └── audit_controls.rb      # Validates audit policy configuration
│   └── inspec.yml                 # InSpec profile metadata
├── scripts/
│   ├── Set-AuditPolicy.ps1        # Standalone audit policy configurator
│   ├── Disable-VulnerableServices.ps1
│   └── Install-Sysmon.ps1         # Downloads Sysmon + SwiftOnSecurity config
├── drift/
│   └── Detect-Drift.ps1           # Scheduled compliance drift detection
├── reports/                       # Generated HTML compliance reports (git-ignored)
├── docs/
│   └── cis_control_mapping.md     # Full CIS ID → Task → InSpec mapping
├── .github/
│   └── workflows/
│       └── lint.yml               # CI: YAML lint + InSpec syntax check
├── Vagrantfile                    # Spin up a test Windows Server VM
├── Run-Toolkit.ps1                # One-click: Harden → Validate → Report
└── README.md
```

---

## Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/Windows-Server-Hardening-Toolkit.git
cd Windows-Server-Hardening-Toolkit
```

### 2. Configure your target server
Edit `ansible/inventory/hosts.yml`:
```yaml
windows_servers:
  hosts:
    win-server-01:
      ansible_host: 192.168.1.100
      ansible_user: Administrator
      ansible_password: "YourPassword"
      ansible_connection: winrm
      ansible_winrm_transport: basic
```

### 3. Toggle controls in `ansible/group_vars/all.yml`
```yaml
enable_account_hardening: true
enable_network_hardening: true
enable_service_hardening: true
enable_audit_policy: true
enable_sysmon: true
# Set to false for roles you want to skip
```

### 4. Run the toolkit (one command)
```powershell
.\Run-Toolkit.ps1 -InventoryFile .\ansible\inventory\hosts.yml
```

This will:
1. Run all Ansible hardening roles
2. Execute InSpec compliance validation
3. Generate an HTML report in `reports/`

---

## Usage

### Running the Full Hardening Suite
```bash
ansible-playbook ansible/site.yml -i ansible/inventory/hosts.yml
```

### Running Validation Only (Non-destructive audit)
```bash
inspec exec inspec/ -t winrm://Administrator:Password@192.168.1.100 --reporter html:reports/compliance_$(date +%Y%m%d).html
```

### Running a Single Role
```bash
ansible-playbook ansible/site.yml -i ansible/inventory/hosts.yml --tags network_hardening
```

### Enabling Drift Detection
Schedule `drift/Detect-Drift.ps1` as a Windows Scheduled Task to run hourly:
```powershell
.\drift\Detect-Drift.ps1 -Register -IntervalMinutes 60
```

---

## Configuration

All control categories can be toggled on/off in `ansible/group_vars/all.yml`:

```yaml
# === CONTROL TOGGLES ===
enable_account_hardening: true    # CIS Section 1 - 7 controls
enable_network_hardening: true    # CIS Section 18 - 6 controls
enable_service_hardening: true    # CIS Section 5 - 4 controls
enable_audit_policy: true         # CIS Section 17 - 4 controls
enable_sysmon: true               # Sysmon telemetry deployment

# === ACCOUNT POLICY SETTINGS ===
password_history_count: 24
max_password_age: 60
min_password_age: 1
min_password_length: 14

# === LOCKOUT POLICY ===
lockout_threshold: 5
lockout_duration: 30
lockout_observation_window: 30
```

---

## Compliance Reports

After running the toolkit, HTML reports are generated in `reports/`. Example output:

```
📊 Compliance Report - 2024-01-15 14:30:22
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Passed:  19 / 21 controls
❌ Failed:   2 / 21 controls
⚠️  Skipped:  0 / 21 controls

Overall Compliance: 90.5%
```

---

## Lab Environment (Vagrant)

Spin up a local Windows Server 2019 test VM to safely test the toolkit:

```bash
# Requires: VirtualBox + Vagrant + vagrant-winrm plugin
vagrant plugin install vagrant-winrm
vagrant up
```

The VM will boot with:
- Windows Server 2019 evaluation image
- WinRM pre-configured for Ansible connectivity
- Shared folder mapped to the project root

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/add-cis-control-X.X.X`)
3. Add your Ansible task + matching InSpec test
4. Update `docs/cis_control_mapping.md`
5. Submit a Pull Request

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

<div align="center">
<sub>Built as a Security Engineering portfolio project demonstrating CIS compliance automation, Infrastructure as Code, and compliance-as-code principles.</sub>
</div>
