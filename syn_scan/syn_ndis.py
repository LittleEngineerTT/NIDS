from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from datetime import datetime
import threading
import ipaddress
import atexit
import yaml
import os
from cryptography.hazmat.primitives import serialization
from nacl.signing import SigningKey
import base64


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

            to_log = to_block(src, network)
            if to_log >= 0:
                write_log(to_log, src, network, tcp_layer.dport)


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


def write_log(to_log, src, network, port):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open("log.txt", "a") as log_file:
        if to_log == 1:
            log_file.write(f"{timestamp} SYN Scan: {src} -> {port}\n")
            print(f"{timestamp} SYN Scan: {src} -> {port}")
        elif to_log == 2:
            log_file.write(f"{timestamp} SYN Scan: {network} -> {port}\n")
            print(f"{timestamp} SYN Scan: {network} -> {port}")


def get_ports(content_type, content):
    global state, network_state
    if content_type == 0:
        return list(state[content])
    else:
        ports = []
        for ip_src in network_state[content]:
            ports += get_ports(0, ip_src)
        return ports


def sign_message(message: str, private_key_hex: str) -> str:
    try:
        signing_key = SigningKey(bytes.fromhex(private_key_hex))
        # Signing
        signed = signing_key.sign(message.encode())
        return base64.b64encode(signed).decode()
    except Exception as e:
        raise Exception(f"Erreur de signature: {str(e)}")


def save_to_file():
    if not os.path.exists("./config.yaml"):
        print("Error: ./config.yaml missing")
        return
    with open("./config.yaml", "r") as config_file:
        configuration = yaml.safe_load(config_file)

    print("Sending log file...")
    log_path = './log.txt'

    if not os.path.exists(configuration['encryption_key']):
        print("Error: certificate file not found please verify ./config.yaml")
        return

    with open(log_path, "r") as log_file:
        log_data = log_file.read()

    with open(configuration['encryption_key'], "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(private_key_file.read(), None)
        signature = private_key.sign(log_data.encode())

    return base64.b64encode(signature).decode()


if __name__ == '__main__':
    atexit.register(save_to_file)
    clear_state()
    sniff(filter="tcp", iface="lo", prn=log_syn_packet, store=0)
