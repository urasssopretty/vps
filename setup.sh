# /bin/bash
sudo apt update && sudo apt upgrade -y
sudo apt install micro git tcptrack bmon iftop nethogs -y


# SWAP SETUP
sudo falloate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
echo 'vm.swappiness=60' | sudo tee -a /etc/sysctl.conf
echo 'vm.vfs_cache_pressure=50' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

echo "SystemMaxUse=50M" | sudo tee -a /etc/systemd/jounrald.conf
sudo systemctl restart systemd-jounrald

# SETUP SSH


# INSTALL APPS
# wireguard
curl -L https://install.pivpn.io | bash

# xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install


# CLEAR & REBOOT
# sudo journalctl --vacuum-size=5M
sudo apt clean
reboot
