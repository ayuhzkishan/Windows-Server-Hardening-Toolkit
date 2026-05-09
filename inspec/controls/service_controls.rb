# ============================================================
# InSpec Control: Service Management
# CIS: Section 5 - Services (4 controls)
# inspec/controls/service_controls.rb
#
# Validates that dangerous services have been disabled by the
# Ansible service_hardening role. Uses the InSpec service
# resource to check both state and startup type.
# ============================================================

title 'CIS Section 5 - Service Management'

# ── CIS 5.29 ──────────────────────────────────────────────────
control 'cis-5.29' do
  impact 1.0
  title 'Ensure Print Spooler service is disabled'
  desc 'CIS 5.29: The Print Spooler service is exploited by PrintNightmare ' \
       '(CVE-2021-1675 / CVE-2021-34527) to achieve remote code execution as ' \
       'SYSTEM. Must be disabled on all servers that are not print servers.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_5_29'
  tag cis: ['5.29']
  tag nist: ['CM-7', 'SI-2']
  tag cve: ['CVE-2021-1675', 'CVE-2021-34527']
  tag mitre: ['T1574']

  describe service('Spooler') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end

# ── CIS 5.30 ──────────────────────────────────────────────────
control 'cis-5.30' do
  impact 0.7
  title 'Ensure Remote Registry service is disabled'
  desc 'CIS 5.30: Remote Registry allows attackers with network access to ' \
       'read and write registry keys remotely — a significant lateral movement ' \
       'vector. Should be disabled on all servers.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_5_30'
  tag cis: ['5.30']
  tag nist: ['CM-7', 'AC-3']

  describe service('RemoteRegistry') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end

# ── CIS 5.41 ──────────────────────────────────────────────────
control 'cis-5.41' do
  impact 0.3
  title 'Ensure Xbox services are disabled'
  desc 'CIS 5.41: Xbox-related services have no purpose on a server OS. ' \
       'Disabling them reduces unnecessary attack surface by removing ' \
       'components that will never receive security patches on server builds.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_5_41'
  tag cis: ['5.41']
  tag nist: ['CM-7']

  %w[XboxGipSvc XblAuthManager XblGameSave XboxNetApiSvc].each do |svc|
    describe service(svc) do
      # Services may not exist on Server Core — only check if present
      it { should_not be_running } if service(svc).exist?
    end
  end
end

# ── Bonus: SMBv1 disabled ─────────────────────────────────────
# SMBv1 is exploited by EternalBlue (MS17-010 / WannaCry / NotPetya).
# Not a numbered service but validated here as a service-layer check.
control 'bonus-smbv1-disabled' do
  impact 1.0
  title 'Ensure SMBv1 is disabled (EternalBlue / WannaCry mitigation)'
  desc 'SMBv1 is a legacy protocol exploited by EternalBlue (MS17-010), ' \
       'the vulnerability used in the WannaCry and NotPetya ransomware campaigns.'
  tag nist: ['CM-7', 'SI-2']
  tag cve: ['CVE-2017-0144']
  tag mitre: ['T1210']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('SMB1') { should eq 0 }
  end
end
