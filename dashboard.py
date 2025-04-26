from flask import Flask, render_template, jsonify
from threading import Thread
from scapy.all import sniff, IP, TCP, IPv6
from collections import defaultdict
from datetime import datetime
import time


app = Flask(__name__)
alerts = []

scan_log = defaultdict(list)

def is_internal_ip(ip):
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")



def detect_port_scan(packet):
    global alerts

    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
    elif packet.haslayer(IPv6) and packet.haslayer(TCP):
        src_ip = packet[IPv6].src
        dst_port = packet[TCP].dport
    else:
        return  # not TCP

    timestamp = time.time()
    scan_log[src_ip].append((dst_port, timestamp))
    scan_log[src_ip] = [(p, t) for p, t in scan_log[src_ip] if timestamp - t < 30]
    ports_accessed = set(p for p, _ in scan_log[src_ip])

    if len(ports_accessed) > 0:
        readable_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Determine severity based on number of ports accessed
    if len(ports_accessed) <= 3:
        severity = "low"
    elif len(ports_accessed) <= 10:
        severity = "medium"
    else:
        severity = "high"

    internal = is_internal_ip(src_ip)

    alert = {
        "time": readable_time,
        "src_ip": src_ip,
        "ports": sorted(ports_accessed),
        "severity": severity,
        "internal": internal
    }

    print(f"[{readable_time}] Activity from {src_ip} on ports: {sorted(ports_accessed)} (Severity: {severity})")
    alerts.append(alert)
    scan_log[src_ip] = []



@app.route('/')
def index():
    return render_template('index.html')


@app.route('/alerts')
def get_alerts():
    return jsonify(alerts)

@app.route('/clear_alerts',methods=['POST'])
def clear_alerts():
    global alerts
    alerts = []
    return jsonify({"status": "cleared"})


def start_sniffer():
    sniff(prn=detect_port_scan, store=0)


if __name__ == '__main__':
    sniffer_thread = Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()
    app.run(debug=True, host="0.0.0.0")
