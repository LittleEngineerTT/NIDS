from scapy.all import sniff, IP, TCP
from NdisDOS import detect_syn_flood, block_ip

def start_sniffing(interface="lo"):
    print(f"Interface monitoring...")
    sniff(iface=interface, filter="tcp", prn=detect_syn_flood)

if __name__ == "__main__":
    start_sniffing()
