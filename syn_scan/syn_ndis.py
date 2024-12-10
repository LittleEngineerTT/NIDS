from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
import threading
import ipaddress


state = {}
network_state = {}

def clear_state():
    global state, network_state
    state.clear()  # Clear the data state
    network_state.clear()
    # schedule the task to run every minutes
    threading.Timer(60, clear_state).start()


def get_network_from_ip(ip):
    # get /24 from IP
    try:
        network = ipaddress.ip_interface(f"{ip}/24").network
        return str(network)
    except ValueError:
        return None


def log_syn_packet(packet):
    global state
    # Is tcp
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet.getlayer(IP)
        tcp_layer = packet.getlayer(TCP)
        src = str(ip_layer.src)
        # Is SYN packet
        if tcp_layer.flags == 'S':
            if src not in state.keys():
                state[src] = set()
            state[src].add(tcp_layer.dport)
            network = get_network_from_ip(src)
            print(network)

            to_log = to_block(src, network)
            if to_log >= 0:
                write_log(to_log, src, network,)
    print(network_state)


def to_block(src, network):
    global state, network_state

    # Check for a network scan
    if network is not None:
        if network not in network_state.keys():
            network_state[network] = set()
        network_state[network].add(src)
        if len(network_state[network]) >= 3:
            return 2

    # Check for a one ip scan
    if src in state.keys():
        return 1 if len(state[src]) >= 3 else -1
    else:
        return -1


def write_log(to_log, src, network):
    with open("log.txt", "a") as log_file:
        if to_log == 1:
            log_file.write(f"SYN Scan: {src} -> {get_ports(0, src)}\n")
            print(f"SYN Scan: {src} -> {get_ports(0, src)}")
        elif to_log == 2:
            log_file.write(f"SYN Scan: {network} -> {get_ports(1, network)}\n")
            print(f"SYN Scan: {network} -> {get_ports(1, network)}")


def get_ports(content_type, content):
    global state, network_state
    if content_type == 0:
        return list(state[content])
    else:
        ports = []
        for ip_src in network_state[content]:
            ports.append(get_ports(0, ip_src))
        return ports


if __name__ == '__main__':
    clear_state()
    sniff(filter="tcp", iface="lo", prn=log_syn_packet, store=0)
