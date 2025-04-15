# 🛡️ Intrusion Detection System (IDS) – Real-Time Flask Dashboard

This project is a lightweight, Python-based **Intrusion Detection System (IDS)** built using Scapy and Flask. It monitors network traffic for suspicious activity, specifically **port scanning**, and displays real-time alerts in a clean, browser-based dashboard.

## 🔍 Features

- Captures TCP packets in real-time using Scapy
- Detects port scans (10+ unique ports in 5 seconds from same IP)
- Displays alerts in a live-updating Flask dashboard
- Web-accessible from any machine (hosted on Azure VM)
- Fully customizable and beginner-friendly


![Terminal Alert](screenshots/alert-terminal.png)
![Dashboard View](screenshots/dashboard-view.png)

## 🚀 Demo

To test:
```bash
nmap -T4 -p 1-1000 <VM_IP>
