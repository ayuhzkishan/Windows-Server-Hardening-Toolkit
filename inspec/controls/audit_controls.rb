# ============================================================
# InSpec Control: Audit Policy
# CIS: Section 17 - Advanced Audit Policy (4 controls)
# inspec/controls/audit_controls.rb
#
# Validates that auditpol.exe settings were correctly applied
# by the Ansible audit_policy role. Uses InSpec's audit_policy
# resource which calls auditpol /get internally.
#
# Valid values: "Success", "Failure", "Success and Failure", 
#               "No Auditing"
# ============================================================

title 'CIS Section 17 - Advanced Audit Policy'

# ── CIS 17.1.1 ────────────────────────────────────────────────
control 'cis-17.1.1' do
  impact 0.7
  title 'Ensure Credential Validation is set to Success and Failure'
  desc 'CIS 17.1.1: Auditing credential validation events captures both ' \
       'successful and failed authentication attempts, forming the basis ' \
       'of brute-force and pass-the-hash detection rules in a SIEM.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_17_1_1'
  tag cis: ['17.1.1']
  tag nist: ['AU-2', 'AU-12']

  describe audit_policy do
    its('Credential Validation') { should eq 'Success and Failure' }
  end
end

# ── CIS 17.2.1 ────────────────────────────────────────────────
control 'cis-17.2.1' do
  impact 0.7
  title 'Ensure Application Group Management is set to Success and Failure'
  desc 'CIS 17.2.1: Auditing group management changes detects unauthorized ' \
       'privilege escalation — for example, an attacker adding themselves to ' \
       'the Administrators group.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_17_2_1'
  tag cis: ['17.2.1']
  tag nist: ['AU-2', 'AC-2']

  describe audit_policy do
    its('Application Group Management') { should eq 'Success and Failure' }
  end
end

# ── CIS 17.5.1 ────────────────────────────────────────────────
control 'cis-17.5.1' do
  impact 0.7
  title 'Ensure Account Lockout is set to Failure'
  desc 'CIS 17.5.1: Failure-only auditing for Account Lockout generates ' \
       'Windows Event ID 4740, the primary indicator for brute-force and ' \
       'password-spray attack detection.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_17_5_1'
  tag cis: ['17.5.1']
  tag nist: ['AU-2', 'AC-7']
  tag event_id: ['4740']

  describe audit_policy do
    its('Account Lockout') { should eq 'Failure' }
  end
end

# ── CIS 17.5.4 ────────────────────────────────────────────────
control 'cis-17.5.4' do
  impact 1.0
  title 'Ensure Logon is set to Success and Failure'
  desc 'CIS 17.5.4: Logon event auditing generates Event IDs 4624 (success) ' \
       'and 4625 (failure). These are the single most important events for ' \
       'incident response, lateral movement detection, and SIEM alerting.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_17_5_4'
  tag cis: ['17.5.4']
  tag nist: ['AU-2', 'AC-17']
  tag event_id: ['4624', '4625']
  tag mitre: ['T1078', 'T1021']

  describe audit_policy do
    its('Logon') { should eq 'Success and Failure' }
  end
end

# ── BONUS: Process Creation ────────────────────────────────────
control 'bonus-process-creation-audit' do
  impact 0.7
  title 'Ensure Process Creation auditing is enabled (Sysmon correlation)'
  desc 'Process Creation events (Event ID 4688) log every process that starts ' \
       'on the system. Combined with Sysmon Event ID 1, this is the foundation ' \
       'of living-off-the-land (LotL) attack detection.'
  tag nist: ['AU-2', 'CM-6']
  tag event_id: ['4688']
  tag mitre: ['T1059', 'T1218']

  describe audit_policy do
    its('Process Creation') { should eq 'Success' }
  end
end

# ── BONUS: Command Line Logging ────────────────────────────────
control 'bonus-cmdline-logging' do
  impact 0.7
  title 'Ensure command line parameters are included in Process Creation events'
  desc 'Without command line logging, Event ID 4688 only shows the process name. ' \
       'Enabling this registry key adds the full command line, making LOLBin ' \
       'abuse (e.g., powershell.exe -enc ...) visible in the Security event log.'
  tag nist: ['AU-3']
  tag mitre: ['T1059.001']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit') do
    its('ProcessCreationIncludeCmdLine_Enabled') { should eq 1 }
  end
end
