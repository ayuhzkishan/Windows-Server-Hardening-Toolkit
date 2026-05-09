# ============================================================
# InSpec Control: Account Policies
# CIS: Section 1 - Account Policies (7 controls)
# inspec/controls/account_controls.rb
#
# Validates that the Ansible account_hardening role applied
# all security policy settings correctly using secedit.
# ============================================================

title 'CIS Section 1 - Account Policies'

# ── CIS 1.1.1 ─────────────────────────────────────────────────
control 'cis-1.1.1' do
  impact 1.0
  title 'Ensure password history is set to 24 or more passwords'
  desc 'CIS 1.1.1: Prevents users from reusing recent passwords. ' \
       'Mitigates credential reuse attacks.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_1_1_1'
  tag cis: ['1.1.1']
  tag nist: ['IA-5']

  describe security_policy do
    its('PasswordHistorySize') { should be >= 24 }
  end
end

# ── CIS 1.1.2 ─────────────────────────────────────────────────
control 'cis-1.1.2' do
  impact 0.7
  title 'Ensure maximum password age is 365 days or fewer'
  desc 'CIS 1.1.2: Forces periodic password changes to limit the window ' \
       'of credential exposure after a breach.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_1_1_2'
  tag cis: ['1.1.2']
  tag nist: ['IA-5']

  describe security_policy do
    its('MaximumPasswordAge') { should be <= 60 }
    its('MaximumPasswordAge') { should be > 0 }
  end
end

# ── CIS 1.1.3 ─────────────────────────────────────────────────
control 'cis-1.1.3' do
  impact 0.5
  title 'Ensure minimum password age is 1 or more day(s)'
  desc 'CIS 1.1.3: Prevents users from immediately cycling through passwords ' \
       'to get back to a favourite, defeating password history controls.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_1_1_3'
  tag cis: ['1.1.3']
  tag nist: ['IA-5']

  describe security_policy do
    its('MinimumPasswordAge') { should be >= 1 }
  end
end

# ── CIS 1.1.4 ─────────────────────────────────────────────────
control 'cis-1.1.4' do
  impact 1.0
  title 'Ensure minimum password length is 14 or more characters'
  desc 'CIS 1.1.4: Longer passwords exponentially increase the time ' \
       'required for brute-force attacks.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_1_1_4'
  tag cis: ['1.1.4']
  tag nist: ['IA-5']

  describe security_policy do
    its('MinimumPasswordLength') { should be >= 14 }
  end
end

# ── CIS 1.1.5 ─────────────────────────────────────────────────
control 'cis-1.1.5' do
  impact 1.0
  title 'Ensure password complexity requirements are enabled'
  desc 'CIS 1.1.5: Requires passwords to contain uppercase, lowercase, ' \
       'digits, and special characters to resist dictionary attacks.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_1_1_5'
  tag cis: ['1.1.5']
  tag nist: ['IA-5']

  describe security_policy do
    its('PasswordComplexity') { should eq 1 }
  end
end

# ── CIS 1.2.1 ─────────────────────────────────────────────────
control 'cis-1.2.1' do
  impact 1.0
  title 'Ensure account lockout threshold is 5 or fewer invalid logon attempts'
  desc 'CIS 1.2.1: Limits the number of failed login attempts before an account ' \
       'is locked out. Mitigates automated brute-force and password-spray attacks.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_1_2_1'
  tag cis: ['1.2.1']
  tag nist: ['AC-7']

  describe security_policy do
    its('LockoutBadCount') { should be <= 5 }
    its('LockoutBadCount') { should be > 0 }
  end
end

# ── CIS 1.2.2 ─────────────────────────────────────────────────
control 'cis-1.2.2' do
  impact 0.7
  title 'Ensure account lockout duration is 15 or more minutes'
  desc 'CIS 1.2.2: Ensures locked accounts remain locked long enough to ' \
       'deter automated attacks, without requiring manual administrator unlock.'
  desc 'remediation', 'Run ansible-playbook site.yml --tags cis_1_2_2'
  tag cis: ['1.2.2']
  tag nist: ['AC-7']

  describe security_policy do
    its('LockoutDuration') { should be >= 15 }
  end
end
