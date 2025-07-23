# 🔥 FirewallFalcon Manager

Free SSH/V2RAY/DNSTT/WEBSOCKET Manager — **FirewallFalcon Manager**

---

## 🚀 Support FirewallFalcon Manager

Our script is always **FREE**—your donation keeps it that way and powers new features!

- **Donate Tron / TRX (TRC-20):**
  ```
  TM2AfVAWQJiuriGC6KoTmsAJuUTTBd2f1R
  ```
- **Binance Pay:** `885652061`

---

## ⚙️ Automated Installation (Recommended)

Run the following command in your terminal to quickly set up FirewallFalcon Manager:

```sh
curl -L -o install.sh "https://raw.githubusercontent.com/SLSTunnel/FirewallFalcon-Manager/refs/heads/main/install.sh" && chmod +x install.sh && sudo ./install.sh && rm install.sh
```

---

## 🛠️ New Features & Enhancements (2024)

- **Nginx Reverse Proxy**
  - Listens on ports: **81** (status), **80** & **8080** (WebSocket), **8880** (SOCKS), **1194** (OpenVPN over WebSocket)
  - Config file: `/etc/nginx/conf.d/falcon.conf`
- **Dropbear SSH**
  - Installed and enabled on ports: **443**, **444**, **445**
- **OpenVPN**
  - Installed and enabled on port: **1194**
  - Accessible via WebSocket proxy (connect OpenVPN client to port 1194)
- **Improved Install Scripts**
  - User prompts, error handling, and logging to `/var/log/falcon_install.log`
  - Idempotent and safe to re-run

---

## ⚡️ Port Configuration

- **Ports 80 & 8080:** WebSocket Proxy (Nginx → backend)
- **Port 8880:** SOCKS Proxy (Nginx → backend)
- **Port 1194:** OpenVPN (Nginx → backend, supports WebSocket)
- **Ports 443, 444, 445:** Dropbear SSH
- **Port 81:** Nginx status page

---

## ✅ How to Verify Everything Works

1. **Nginx**
   - Check status: `systemctl status nginx`
   - Confirm `/etc/nginx/conf.d/falcon.conf` exists
   - Test status page: `curl http://localhost:81`
2. **Dropbear**
   - Check status: `systemctl status dropbear`
   - Test SSH: `ssh -p 443 user@your_server_ip`
3. **OpenVPN**
   - Check status: `systemctl status openvpn`
   - Connect OpenVPN client to port 1194 (WebSocket supported)
4. **WebSocket/SOCKS**
   - Test WebSocket: Connect to ports 80 or 8080
   - Test SOCKS: Connect to port 8880
5. **Logs**
   - Review `/var/log/falcon_install.log` for install and setup details

---

## 🚦 Core Features

- 🚀 **SSH WebSocket Proxy:** Tunnel SSH traffic over WebSockets with custom port selection.
- 🔒 **SSH over SSL/TLS:** Encapsulate SSH connections in a robust TLS layer for enhanced security.
- 👥 **User Management:** Easily create, manage, and control user access to your servers.
- 🛡️ **Integrated Xray Panel:** Leverage Xray's advanced proxy capabilities for privacy and circumvention.

---

![FirewallFalcon Manager User Interface](https://github.com/user-attachments/assets/30873b61-9bfd-4405-bde8-44fb0cfa4113)
![Dashboard Example](https://github.com/user-attachments/assets/575d5380-3b82-4953-9485-ea26e9056724)

---

> _Thank you for using and supporting FirewallFalcon Manager!_
