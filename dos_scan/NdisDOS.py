from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import os
import threading
import subprocess


SYN_THRESHOLD = 10

TIME_PERIOD = 5

syn_counts = defaultdict(int)

last_check_time = time.time()

blocked_ips = set()

def block_ip(ip):
    if ip not in blocked_ips:
        print(f"[ACTION] IP : {ip} was blocked with iptables.")
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        os.system(f'echo "iptables -D INPUT -s {ip} -j DROP" | sudo at now + 1 minute')

def detect_syn_flood(packet):
    global last_check_time
    current_time = time.time()

    if current_time - last_check_time > TIME_PERIOD:
        syn_counts.clear()
        last_check_time = current_time

    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        ip_src = packet[IP].src
        syn_counts[ip_src] += 1

        if syn_counts[ip_src] > SYN_THRESHOLD:
            #write_log(1, ip_src, None, "80", "DOS SCAN")
            block_ip(ip_src)  # Bloquer l'IP

