from scapy.all import sniff, TCP
from collections import defaultdict
import time
import sys
sys.path.append('..')
from syn_scan.nids import write_log, block_ip

# dict to keep track of connection attempts
connection_attempts = defaultdict(list)

MAX_ATTEMPTS = 10 * 2 # multiply by two because SSH initiate two request
TIME_WINDOW = 60  # in seconds
TARGET_PORT = 22

def detect_bruteforce(packet):
    # check for TCP SYN packets to the target port
    if packet.haslayer(TCP) and packet[TCP].dport == TARGET_PORT and packet[TCP].flags == "S":
        src_ip = packet[0][1].src  # src ip
        current_time = time.time()

        # add the timestamp to the list for this source IP
        connection_attempts[src_ip].append(current_time)

        # remove timestamps that are outside the time window
        connection_attempts[src_ip] = [t for t in connection_attempts[src_ip] if current_time - t <= TIME_WINDOW]

        # check if the number of attempts exceeds the threshold
        if len(connection_attempts[src_ip]) >= MAX_ATTEMPTS:
            write_log(1, src_ip, None, "2222", "SSH BRUTEFORCE")
            # clear the list to avoid repeated alerts
            connection_attempts[src_ip] = []
            block_ip(src_ip, 0)

print(f"Started Anti SSH Bruteforce NIDS on TCP port {TARGET_PORT} for potential brute force attempts...")
# we directly filter by port here!
#sniff(filter=f"tcp and dst port {TARGET_PORT}", prn=detect_bruteforce, store=0, iface="lo")

