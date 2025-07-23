#!/bin/bash

LOG_FILE="/var/log/falcon_install.log"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

prompt_continue() {
  read -p "Proceed with FirewallFalcon installation? (y/n): " yn
  case $yn in
    [Yy]*) ;;
    *) log "Installation aborted by user."; exit 1;;
  esac
}

log "Starting FirewallFalcon installation."
prompt_continue

log "Downloading SSH configuration..."
sudo wget -O /etc/ssh/sshd_config https://raw.githubusercontent.com/firewallfalcons/FirewallFalcon-Manager/refs/heads/main/ssh > /dev/null 2>&1
if [ $? -eq 0 ]; then
  log "SSH configuration downloaded successfully."
else
  log "Failed to download SSH configuration."; exit 1
fi

log "Restarting SSH service..."
sudo systemctl restart sshd || sudo service sshd restart || sudo systemctl restart ssh || sudo service ssh restart > /dev/null 2>&1
if [ $? -eq 0 ]; then
  log "SSH service restarted successfully."
else
  log "Failed to restart SSH service."; exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)
    log "Detected x86_64 architecture. Running 64install.sh."
    curl -L -o 64install.sh "https://github.com/firewallfalcons/FirewallFalcon-Manager/raw/refs/heads/main/64install.sh" && chmod +x 64install.sh && sudo ./64install.sh && rm 64install.sh
    ;;
  aarch64 | arm64)
    log "Detected ARM architecture. Running arminstall.sh."
    curl -L -o arminstall.sh "https://github.com/firewallfalcons/FirewallFalcon-Manager/raw/refs/heads/main/arminstall.sh" && chmod +x arminstall.sh && sudo ./arminstall.sh && rm arminstall.sh
    ;;
  *)
    log "Unsupported architecture: $ARCH"; exit 1
    ;;
esac

log "FirewallFalcon installation completed."

