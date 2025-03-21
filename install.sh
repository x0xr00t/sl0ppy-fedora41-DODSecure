#!/bin/bash
#
# Author: p.hoogeveen
# AKA   : x0xr00t
# Build : 21032025
# DoD Security Package Installer for Fedora


set -e  # Exit on error
LOGFILE="/var/log/dod_install.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo -e "\n[+] 🚀 Installing Security Packages for DoD-Level Hardening...\n"

# Ensure system is up to date
echo "[+] Updating system..."
sudo dnf update -y

# Install core security tools
echo "[+] Installing required security packages..."
sudo dnf install -y \
    epel-release \
    suricata suricata-update \
    fail2ban \
    firewalld \
    nano curl wget nmap \
    policycoreutils-python-utils \
    aide audit \
    openscap-scanner \
    chrony \
    dnscrypt-proxy \
    yara \
    clamav clamav-update \
    rsyslog \
    logwatch

# Enable & start critical services
echo "[+] Enabling essential security services..."
sudo systemctl enable --now suricata
sudo systemctl enable --now fail2ban
sudo systemctl enable --now firewalld
sudo systemctl enable --now auditd
sudo systemctl enable --now chronyd
sudo systemctl enable --now dnscrypt-proxy
sudo systemctl enable --now clamav-freshclam

# Update ClamAV database
echo "[+] Updating ClamAV virus definitions..."
sudo freshclam

# Verify installation
echo "[+] Verifying installed packages..."
dnf list --installed | grep -E "suricata|fail2ban|firewalld|aide|audit|openscap|chrony|dnscrypt|yara|clamav"

echo -e "\n💀 [SUCCESS] All security packages have been installed! 💀"
