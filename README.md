🛡️ Intrusion Detection System (IDS) – Real-Time Flask Dashboard
This project is a lightweight, Python-based Intrusion Detection System (IDS) built using Scapy and Flask.
It monitors network traffic for suspicious activity — specifically port scanning — and displays real-time alerts through a clean, browser-based dashboard.

🔍 Features
Captures TCP packets live using Scapy

Detects potential port scans (customizable thresholds)

Color-coded alerts based on threat severity:

🟩 Low (1–3 ports)

🟨 Medium (4–10 ports)

🟥 High (more than 10 ports)

Highlights External IP addresses with a blue badge

Auto-refreshing web dashboard (every 3 seconds)

Manual "Clear Alerts" button to reset dashboard

Supports IPv4 and IPv6 traffic

Beginner-friendly and customizable for learning and extension

🚀 Demo and Testing
To simulate a port scan against the IDS:

bash
Copy
Edit
nmap -sT -p 1-1000 -Pn <target_IP_address>

📢 If using Termux or another limited environment, use -sT (TCP Connect Scan) since -sS (Stealth Scan) requires root.

🛠 Installation and Setup
Clone this repository:

bash
Copy
Edit
git clone https://github.com/viznate/ids-flask-sniffer.git
cd ids-flask-sniffer
Install required Python packages:

bash
Copy
Edit
pip install flask scapy
Run the IDS server (requires sudo/admin for packet sniffing):

bash
Copy
Edit
sudo python dashboard.py
Access the dashboard in your browser:

bash
Copy
Edit
http://localhost:5000
or

bash
Copy
Edit
http://<your_machine_IP>:5000
🌐 Hosting Notes
Can be hosted locally or deployed on a VM (tested on Azure Virtual Machine and local Windows PC).

Ensure firewall settings allow inbound traffic on the listening port (default: 5000).

Cloud VM deployment might restrict packet sniffing at the raw interface level — local deployment recommended for full functionality.

⚙️ Technologies Used
Python 3

Flask – Web framework

Scapy – Packet capture and analysis

HTML/CSS/JavaScript – Dashboard front-end

📜 License
This project is open-source for educational and portfolio purposes.

📢 Final Notes
This IDS was built for hands-on learning and real-world simulation of basic network threat detection.
It is beginner-friendly, extensible, and provides a strong foundation for future cybersecurity projects.
