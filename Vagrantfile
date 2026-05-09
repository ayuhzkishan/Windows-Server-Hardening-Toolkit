# ============================================================
# Vagrantfile - Windows Server 2019 Test Lab
# Windows Server Hardening Toolkit
#
# Spins up a Windows Server 2019 evaluation VM using VirtualBox.
# WinRM is pre-configured so Ansible can connect immediately.
#
# REQUIREMENTS:
#   - VirtualBox (https://www.virtualbox.org/)
#   - Vagrant (https://www.vagrantup.com/)
#   - vagrant-winrm plugin: vagrant plugin install vagrant-winrm
#
# USAGE:
#   vagrant up                    # Start the VM
#   vagrant provision             # Re-run provisioning
#   vagrant ssh / rdp             # Connect to the VM
#   vagrant destroy               # Delete the VM
# ============================================================

Vagrant.configure("2") do |config|

  # ── Base Box ──────────────────────────────────────────────────
  # Community-maintained Windows Server 2019 evaluation box
  config.vm.box     = "gusztavvargadr/windows-server-2019-standard"
  config.vm.box_url = "https://vagrantcloud.com/gusztavvargadr/windows-server-2019-standard"

  # ── VM Identity ───────────────────────────────────────────────
  config.vm.hostname = "toolkit-lab"

  # ── Network ───────────────────────────────────────────────────
  # Private network so Ansible on the host can reach the VM
  config.vm.network "private_network", ip: "192.168.56.10"

  # RDP access (optional convenience)
  config.vm.network "forwarded_port", guest: 3389, host: 33389, id: "rdp"

  # WinRM ports
  config.vm.network "forwarded_port", guest: 5985, host: 55985, id: "winrm"
  config.vm.network "forwarded_port", guest: 5986, host: 55986, id: "winrm-ssl"

  # ── WinRM Communication ───────────────────────────────────────
  config.vm.communicator = "winrm"
  config.winrm.username  = "vagrant"
  config.winrm.password  = "vagrant"
  config.winrm.transport = :plaintext
  config.winrm.basic_auth_only = true

  # ── Shared Folder ─────────────────────────────────────────────
  # Mount the project root inside the VM for direct script access
  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"

  # ── VirtualBox Settings ───────────────────────────────────────
  config.vm.provider "virtualbox" do |vb|
    vb.name   = "windows-hardening-lab"
    vb.memory = 4096
    vb.cpus   = 2
    vb.gui    = false

    # Performance tweaks for Windows VMs
    vb.customize ["modifyvm", :id, "--vram",            "128"]
    vb.customize ["modifyvm", :id, "--clipboard",       "bidirectional"]
    vb.customize ["modifyvm", :id, "--draganddrop",     "bidirectional"]
    vb.customize ["modifyvm", :id, "--audio",           "none"]
    vb.customize ["modifyvm", :id, "--usb",             "off"]
    vb.customize ["modifyvm", :id, "--accelerate3d",    "off"]
  end

  # ── Provisioning: Baseline Setup ──────────────────────────────
  # Sets up the VM to be ready for Ansible hardening.
  # Note: This uses PowerShell inline — the Ansible hardening runs
  # from the HOST machine pointing at this VM's IP.
  config.vm.provision "shell", inline: <<-SHELL, privileged: true
    Write-Host "=== Windows Server Hardening Lab — Initial Setup ===" -ForegroundColor Cyan

    # Ensure WinRM allows Ansible connections
    winrm quickconfig -quiet
    winrm set winrm/config/service '@{AllowUnencrypted="true"}'
    winrm set winrm/config/service/auth '@{Basic="true"}'
    Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value "*" -Force

    # Set PowerShell execution policy
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

    Write-Host "✅ WinRM configured. VM ready for Ansible." -ForegroundColor Green
    Write-Host "" 
    Write-Host "   Next step: Run the toolkit from your HOST machine:" -ForegroundColor Yellow
    Write-Host "   .\\Run-Toolkit.ps1 -Target 'winrm://vagrant:vagrant@192.168.56.10'" -ForegroundColor White
  SHELL

end
