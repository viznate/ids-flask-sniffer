from flask import Flask, render_template, jsonify
from threading import Thread
from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime
import time


app = Flask(__name__)
alerts = []

scan_log = defaultdict(list)

def detect_port_scan(packet):
    global alerts
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if packet[TCP].flags == 'S':  # SYN packet
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            timestamp = time.time()
            print(f"[DEBUG] SYN from {src_ip}:{dst_port} at {timestamp}")

            # Add this SYN to the scan log
            scan_log[src_ip].append((dst_port, timestamp))
            # Keep only last 5 seconds of traffic
            scan_log[src_ip] = [(p, t) for p, t in scan_log[src_ip] if timestamp - t < 5]

            # Check if more than 10 unique ports were targeted
            ports_accessed = set(p for p, _ in scan_log[src_ip])
            if len(ports_accessed) > 10:
                readable_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert_msg = f"[{readable_time}] Port scan detected from {src_ip} (ports: {sorted(ports_accessed)})"
                print(alert_msg)
                alerts.append(alert_msg)
                # Optionally clear log to avoid repeated alerts
                scan_log[src_ip] = []

		scan_log[src_ip].append((dst_port, timestamp))
		scan_log[src_ip] = [(p, t) for p, t in scan_log[src_ip] if timestamp - t < 5]
		ports_accessed = set(p for p, _ in scan_log[src_ip])

		if len(ports_accessed) > 10:
			timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
			alert_msg = f'[{timestamp}] Port scan detected from {src_ip} (ports: {sorted(ports_accessed)})'
			print(alert_msg)
			alerts.append(alert_msg)

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/alerts')
def get_alerts():
	return jsonify(alerts)

def start_sniffer():
	sniff(prn=detect_port_scan, filter="tcp", store=0, iface="eth0")

if __name__ == '__main__':
	sniffer_thread = Thread(target=start_sniffer, daemon=True)
	sniffer_thread.start()
	app.run(debug=True, host="0.0.0.0")
