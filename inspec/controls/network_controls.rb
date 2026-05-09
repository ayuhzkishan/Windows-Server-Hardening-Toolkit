# ============================================================
# InSpec Control: Network Security
# CIS: Section 18 - Network Security Settings (6 controls)
# inspec/controls/network_controls.rb
#
# Validates registry-level network hardening applied by the
# Ansible network_hardening role. All tests inspect the
# Windows Registry directly via the registry_key resource.
# ============================================================

title 'CIS Section 18 - Network Security'

# ── CIS 18.5.4.1 ──────────────────────────────────────────────
control 'cis-18.5.4.1' do
  impact 1.0
  title 'Ensure LLMNR is disabled'
  desc 'CIS 18.5.4.1: LLMNR is exploited by Responder to intercept ' \
       'authentication hashes via name resolution poisoning. Disabling ' \
       'it eliminates this attack vector entirely.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_18_5_4_1'
  tag cis: ['18.5.4.1']
  tag nist: ['CM-7', 'SC-8']

  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient') do
    it { should exist }
    its('EnableMulticast') { should eq 0 }
  end
end

# ── CIS 18.5.5.1 ──────────────────────────────────────────────
control 'cis-18.5.5.1' do
  impact 0.7
  title 'Ensure NetBIOS Node Type is set to P-Node (no broadcasts)'
  desc 'CIS 18.5.5.1: P-Node (value 2) disables broadcast-based NetBIOS ' \
       'name resolution, preventing NBNS poisoning attacks (e.g., Responder).'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_18_5_5_1'
  tag cis: ['18.5.5.1']
  tag nist: ['CM-7', 'SC-8']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters') do
    it { should exist }
    its('NodeType') { should eq 2 }
  end
end

# ── CIS 18.5.14.1 ─────────────────────────────────────────────
control 'cis-18.5.14.1' do
  impact 1.0
  title 'Ensure WDigest Authentication is disabled'
  desc 'CIS 18.5.14.1: WDigest causes Windows to store plaintext credentials ' \
       'in LSASS memory. Disabling it prevents tools like Mimikatz from ' \
       'dumping cleartext passwords from memory.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_18_5_14_1'
  tag cis: ['18.5.14.1']
  tag nist: ['IA-5', 'SC-28']
  tag mitre: ['T1003.001']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest') do
    it { should exist }
    its('UseLogonCredential') { should eq 0 }
  end
end

# ── CIS 18.9.97.2 ─────────────────────────────────────────────
control 'cis-18.9.97.2' do
  impact 1.0
  title 'Ensure LSA Protection (RunAsPPL) is enabled'
  desc 'CIS 18.9.97.2: RunAsPPL protects the LSASS process by preventing ' \
       'unauthorized code (including kernel drivers) from reading its memory. ' \
       'This is the primary defence against Mimikatz credential dumping.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_18_9_97_2'
  tag cis: ['18.9.97.2']
  tag nist: ['IA-5', 'SC-28']
  tag mitre: ['T1003', 'T1055']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    its('RunAsPPL') { should eq 1 }
  end
end

# ── CIS 18.5.8.1 ──────────────────────────────────────────────
control 'cis-18.5.8.1' do
  impact 1.0
  title 'Ensure SMB server digital signing is required'
  desc 'CIS 18.5.8.1: SMB signing prevents man-in-the-middle attacks ' \
       'and NTLM relay attacks (e.g., Responder + ntlmrelayx) by ' \
       'cryptographically authenticating each SMB packet.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_18_5_8_1'
  tag cis: ['18.5.8.1']
  tag nist: ['SC-8', 'SI-3']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('RequireSecuritySignature') { should eq 1 }
    its('EnableSecuritySignature') { should eq 1 }
  end
end

# ── CIS 18.6.1 ────────────────────────────────────────────────
control 'cis-18.6.1' do
  impact 0.5
  title 'Ensure IPv6 is disabled if not required'
  desc 'CIS 18.6.1: A value of 255 (0xFF) disables all IPv6 components. ' \
       'Reduces attack surface on servers that do not use IPv6.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_18_6_1'
  tag cis: ['18.6.1']
  tag nist: ['CM-7']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters') do
    it { should exist }
    its('DisabledComponents') { should eq 255 }
  end
end
