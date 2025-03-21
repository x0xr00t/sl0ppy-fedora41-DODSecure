#!/bin/bash
#
# Author: p.hoogeveen
# AKA   : x0xr00t
# Build : 21032025
#
# DoD-Standard Security Hardening Script for Fedora

set -e  # Exit on error
LOGFILE="/var/log/dod_hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo -e "\n[+] 🚀 DoD Security Hardening for Fedora Starting...\n"

### 1️⃣ Update System & Install Security Packages
#echo "[+] Updating system & installing security tools..."
#sudo dnf update -y
#sudo dnf install -y epel-release suricata suricata-update fail2ban firewalld nano curl wget nmap policycoreutils-python-utils aide audit openscap-scanner chrony dnscrypt-proxy

### 2️⃣ Kernel & Memory Hardening
echo "[+] Applying kernel-level security settings..."
sudo bash -c 'cat << EOF >> /etc/sysctl.conf
# DoD Kernel Security Hardening
kernel.kptr_restrict=2
kernel.randomize_va_space=2
kernel.exec-shield=1
kernel.dmesg_restrict=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv6.conf.all.disable_ipv6=1
EOF'
sudo sysctl --system

### 3️⃣ Harden SELinux Policies
echo "[+] Enforcing SELinux..."
sudo setenforce 1
sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

### 4️⃣ Install & Configure AIDE (File Integrity Monitoring)
echo "[+] Setting up AIDE for rootkit detection..."
sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
echo "0 2 * * * root /usr/sbin/aide --check" | sudo tee -a /etc/crontab

### 5️⃣ Restrict Systemd Services (Prevent Privilege Escalation)
echo "[+] Locking down systemd services..."
sudo systemctl mask ctrl-alt-del.target
sudo systemctl mask debug-shell.service
sudo systemctl mask systemd-coredump.socket

### 6️⃣ Harden SSH (Prevent Brute Force & Backdoors)
echo "[+] Securing SSH..."
sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
echo "AllowUsers adminuser" | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart sshd

### 7️⃣ Enable Auditd (Advanced Logging)
echo "[+] Enabling audit logging..."
sudo systemctl enable --now auditd
sudo bash -c 'echo "-a always,exit -F arch=b64 -S execve -k exec_logging" > /etc/audit/rules.d/audit.rules'
sudo auditctl -R /etc/audit/rules.d/audit.rules

### 8️⃣ Secure Chrony (Prevent NTP Poisoning)
echo "[+] Securing Chrony..."
sudo systemctl enable --now chronyd
echo "server time.cloudflare.com iburst" | sudo tee -a /etc/chrony.conf
sudo systemctl restart chronyd

### 9️⃣ Harden DNS Security (DNSCrypt-Proxy)
echo "[+] Enabling DNSCrypt..."
sudo systemctl enable --now dnscrypt-proxy

### 🔟 Harden Firewall Rules (Whitelist)
echo "[+] Configuring Firewalld..."
sudo systemctl enable --now firewalld
sudo firewall-cmd --permanent --remove-forward
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload

### 1️⃣1️⃣ Advanced Threat Intelligence (Suricata + YARA)
echo "[+] Configuring Suricata & YARA for advanced threat detection..."
sudo suricata-update add-source et/open https://rules.emergingthreats.net/open/suricata-5.0.0/emerging.rules.tar.gz
sudo suricata-update add-source abuse.ch https://feodotracker.abuse.ch/blocklist/?download=suricata
sudo suricata-update

# **Fix for "error sending ass ruledata request rule exit write"**
echo "[+] Fixing Suricata rule update issue..."

# Check if rule data is correctly initialized
if ! sudo suricata-update --check; then
    echo "[!] Issue detected with Suricata rule updates. Attempting to fix..."
    sudo rm -rf /etc/suricata/rules/*
    sudo suricata-update
    sudo systemctl restart suricata
    echo "[+] Suricata rule update issue fixed!"
else
    echo "[+] Suricata rules are up to date!"
fi

sudo systemctl restart suricata

### 1️⃣2️⃣ Install & Configure Fail2Ban (Auto-Ban Attackers)
echo "[+] Installing Fail2Ban..."
sudo systemctl enable --now fail2ban
echo "[+] Configuring Fail2Ban rules..."
sudo bash -c 'cat << EOF > /etc/fail2ban/jail.local
[suricata]
enabled = true
filter = suricata
logpath = /var/log/suricata/fast.log
maxretry = 2
bantime = 3600
EOF'
sudo systemctl restart fail2ban

### ✅ Final System Checks
echo "[+] Running final security verification..."
sudo aide --check
sudo auditctl -l
sudo firewall-cmd --list-all
sudo suricata-update

echo -e "\n💀 [SUCCESS] Fedora is now **DoD-Secure**! 💀"
