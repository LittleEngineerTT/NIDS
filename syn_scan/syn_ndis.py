from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import threading

state = {}

def clear_state():
    global state
    state.clear()  # Clear the data state
    # schedule the task to run every minutes
    threading.Timer(60, clear_state).start()


def log_syn_packet(packet):
    global state
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
    clear_state()
    sniff(filter="tcp", iface="lo", prn=log_syn_packet, store=0)
