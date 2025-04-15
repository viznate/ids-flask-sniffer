
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

scan_log = defaultdict(list)

def detect_port_scan(packet):
	if packet.haslayer(IP) and packet.haslayer(TCP):
		src_ip = packet[IP].src
		dst_port = packet[TCP].dport
		timestamp = time.time()

		scan_log[src_ip].append((dst_port, timestamp))

		scan_log[src_ip] = [(port, t) for port, t in scan_log[src_ip] if timestamp - t < 5]

		ports_accessed = set([port for port, _ in scan_log[src_ip]])

		if len(ports_accessed) > 10:
			print(f"\n ALERT: Port scan detected from {src_ip} (ports: {ports_accessed})\n")

sniff(prn=detect_port_scan, filter="tcp", store=0, iface="lo")
