#!/bin/bash

# Update package lists
echo "[*] Updating package lists..."
sudo apt update -y || sudo yum update -y

# Install Nmap
echo "[*] Installing Nmap..."
sudo apt install -y nmap || sudo yum install -y nmap

# Install Gobuster
echo "[*] Installing Gobuster..."
sudo apt install -y gobuster || sudo yum install -y gobuster

# Verify installations
echo "[*] Checking installed versions..."
nmap --version
gobuster --help | head -n 1

echo "[*] Installation completed!"
