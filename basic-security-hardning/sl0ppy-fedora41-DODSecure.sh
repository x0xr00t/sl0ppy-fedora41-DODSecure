#!/bin/bash

# DoD-Level Security Automation for Fedora
# Author: PAOCIA | Cyber Warfare Edition

set -e  # Exit on error
LOGFILE="/var/log/secure_fedora.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo -e "\n[+] Starting DoD-Level Security Hardening...\n"

### 1️⃣ Update System & Install Security Tools
echo "[+] Updating system packages..."
sudo dnf update -y
sudo dnf install -y epel-release suricata suricata-update fail2ban firewalld nano curl wget nmap policycoreutils-python-utils

### 2️⃣ Harden Fedora (Kernel, SELinux, Firewalld)
echo "[+] Hardening Fedora OS..."

# Enforce SELinux
echo "[+] Enforcing SELinux..."
sudo setenforce 1
sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

# Disable Packet Forwarding
echo "[+] Disabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=0
echo "net.ipv4.ip_forward = 0" | sudo tee -a /etc/sysctl.conf
sudo sysctl --system

# Kernel Hardening
echo "[+] Applying kernel hardening settings..."
sudo bash -c 'cat << EOF >> /etc/sysctl.conf
kernel.kptr_restrict=2
kernel.randomize_va_space=2
kernel.exec-shield=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
EOF'
sudo sysctl --system

# Harden SSH
echo "[+] Securing SSH..."
sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Disable Unused Services
echo "[+] Disabling unused services..."
for svc in cups avahi-daemon bluetooth rpcbind; do
    sudo systemctl disable --now "$svc"
done

### 3️⃣ Suricata Setup (IDS/IPS Mode)
echo "[+] Installing & Configuring Suricata..."
sudo systemctl enable --now suricata

# Configure Suricata in IPS Mode
sudo bash -c 'cat << EOF > /etc/suricata/suricata.yaml
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
outputs:
  - fast:
      enabled: yes
      filename: /var/log/suricata/fast.log
  - eve-log:
      enabled: yes
      filename: /var/log/suricata/eve.json
EOF'
sudo systemctl restart suricata

### 4️⃣ Add Threat Intelligence Feeds
echo "[+] Adding Suricata Threat Intelligence Feeds..."
sudo suricata-update add-source et/open https://rules.emergingthreats.net/open/suricata-5.0.0/emerging.rules.tar.gz
sudo suricata-update add-source abuse.ch https://feodotracker.abuse.ch/blocklist/?download=suricata
sudo suricata-update
sudo systemctl restart suricata

### 5️⃣ Harden Firewall Rules
echo "[+] Configuring Firewalld..."
sudo systemctl enable --now firewalld
sudo firewall-cmd --permanent --remove-forward
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload

### 6️⃣ Install & Configure Fail2Ban (Auto-Ban Attackers)
echo "[+] Installing Fail2Ban..."
sudo systemctl enable --now fail2ban

# Configure Suricata Fail2Ban Jail
echo "[+] Setting up Fail2Ban for Suricata..."
sudo bash -c 'cat << EOF > /etc/fail2ban/jail.local
[suricata]
enabled = true
filter = suricata
logpath = /var/log/suricata/fast.log
maxretry = 2
bantime = 3600
EOF'
sudo systemctl restart fail2ban

### 7️⃣ Automatic Updates & Logging
echo "[+] Enabling automatic security updates..."
echo "0 3 * * * root dnf update -y && suricata-update && systemctl restart suricata" | sudo tee -a /etc/crontab

### ✅ Final System Checks
echo "[+] Verifying security setup..."
sudo systemctl status suricata | grep "active (running)"
sudo systemctl status fail2ban | grep "active (running)"
sudo sysctl net.ipv4.ip_forward
sudo firewall-cmd --list-all

echo -e "\n💀 [SUCCESS] Your Fedora system is now DoD-Level Secure! 💀"
