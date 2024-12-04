from scapy.all import sniff
from scapy.layers.inet import IP, TCP

def log_syn_packet(packet):
    # Is tcp
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet.getlayer(IP)
        tcp_layer = packet.getlayer(TCP)

        # Is SYN packet, catch it
        if tcp_layer.flags == 'S':
            with open("log.txt", "a") as log_file:
                log_file.write(f"SYN Packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}\n")
                print(f"SYN Packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")

if __name__ == '__main__':
    sniff(filter="tcp", iface="lo", prn=log_syn_packet, store=0)
