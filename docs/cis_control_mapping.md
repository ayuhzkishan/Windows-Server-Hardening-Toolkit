# CIS Benchmark Control Mapping

**Reference:** CIS Microsoft Windows Server 2019 Benchmark v2.0.0  
**Toolkit Version:** 1.0.0  
**Coverage:** 22 Controls across 4 Categories

This document provides full traceability from each CIS Benchmark control ID to its
Ansible implementation task and corresponding Chef InSpec validation test.

---

## Category 1: Account Policies (CIS Section 1)

| CIS ID | Control Name | Ansible Role | Ansible Task | InSpec Test |
|--------|-------------|--------------|--------------|-------------|
| 1.1.1  | Ensure password history is set to 24+ passwords | `account_hardening` | `set_password_history` | `account_controls.rb:control-1.1.1` |
| 1.1.2  | Ensure max password age is 365 days or fewer | `account_hardening` | `set_max_password_age` | `account_controls.rb:control-1.1.2` |
| 1.1.3  | Ensure min password age is 1+ days | `account_hardening` | `set_min_password_age` | `account_controls.rb:control-1.1.3` |
| 1.1.4  | Ensure min password length is 14+ characters | `account_hardening` | `set_min_password_length` | `account_controls.rb:control-1.1.4` |
| 1.1.5  | Ensure password complexity is enabled | `account_hardening` | `set_password_complexity` | `account_controls.rb:control-1.1.5` |
| 1.2.1  | Ensure account lockout threshold is 5 or fewer invalid logon attempts | `account_hardening` | `set_lockout_threshold` | `account_controls.rb:control-1.2.1` |
| 1.2.2  | Ensure account lockout duration is 15+ minutes | `account_hardening` | `set_lockout_duration` | `account_controls.rb:control-1.2.2` |

---

## Category 2: Network Security (CIS Section 18)

| CIS ID | Control Name | Ansible Role | Ansible Task | InSpec Test |
|--------|-------------|--------------|--------------|-------------|
| 18.5.4.1 | Disable LLMNR (Link-Local Multicast Name Resolution) | `network_hardening` | `disable_llmnr` | `network_controls.rb:control-18.5.4.1` |
| 18.5.5.1 | Disable NetBIOS Node Type (prevents NBNS poisoning) | `network_hardening` | `disable_netbios` | `network_controls.rb:control-18.5.5.1` |
| 18.5.14.1 | Disable WDigest Authentication (prevents plaintext creds in memory) | `network_hardening` | `disable_wdigest` | `network_controls.rb:control-18.5.14.1` |
| 18.9.97.2 | Enable LSA Protection (RunAsPPL) to prevent credential dumping | `network_hardening` | `enable_lsa_protection` | `network_controls.rb:control-18.9.97.2` |
| 18.5.8.1 | Enable SMB Server signing (mitigates relay attacks) | `network_hardening` | `enable_smb_signing` | `network_controls.rb:control-18.5.8.1` |
| 18.6.1  | Disable IPv6 if not in use | `network_hardening` | `disable_ipv6` | `network_controls.rb:control-18.6.1` |

---

## Category 3: Service Management (CIS Section 5)

| CIS ID | Control Name | Ansible Role | Ansible Task | InSpec Test |
|--------|-------------|--------------|--------------|-------------|
| 5.29    | Disable Print Spooler service (PrintNightmare mitigation) | `service_hardening` | `disable_print_spooler` | `service_controls.rb:control-5.29` |
| 5.30    | Disable Remote Registry service | `service_hardening` | `disable_remote_registry` | `service_controls.rb:control-5.30` |
| 5.39    | Disable Windows Remote Management (WinRM) if not required | `service_hardening` | `disable_winrm` | `service_controls.rb:control-5.39` |
| 5.41    | Disable Xbox services | `service_hardening` | `disable_xbox_services` | `service_controls.rb:control-5.41` |

---

## Category 4: Audit Policy (CIS Section 17)

| CIS ID | Control Name | Ansible Role | Ansible Task | InSpec Test |
|--------|-------------|--------------|--------------|-------------|
| 17.1.1  | Audit Credential Validation - Success and Failure | `audit_policy` | `set_audit_credential_validation` | `audit_controls.rb:control-17.1.1` |
| 17.2.1  | Audit Application Group Management - Success and Failure | `audit_policy` | `set_audit_app_group_mgmt` | `audit_controls.rb:control-17.2.1` |
| 17.5.1  | Audit Account Lockout - Failure | `audit_policy` | `set_audit_account_lockout` | `audit_controls.rb:control-17.5.1` |
| 17.5.4  | Audit Logon - Success and Failure | `audit_policy` | `set_audit_logon` | `audit_controls.rb:control-17.5.4` |

---

## Summary

| Category | Controls | Ansible Role | InSpec File |
|----------|----------|--------------|-------------|
| Account Policies | 7 | `account_hardening` | `account_controls.rb` |
| Network Security | 6 | `network_hardening` | `network_controls.rb` |
| Service Management | 4 | `service_hardening` | `service_controls.rb` |
| Audit Policy | 4 | `audit_policy` | `audit_controls.rb` |
| **Total** | **21** | — | — |

---

## References

- [CIS Microsoft Windows Server 2019 Benchmark](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines)
