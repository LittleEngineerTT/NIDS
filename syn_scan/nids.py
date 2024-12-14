import argparse
import subprocess
import os

from scapy.layers.inet import IP, TCP
from datetime import datetime
import threading
import ipaddress
import smtplib
from email.mime.text import MIMEText
from cryptography.fernet import Fernet

state = {}
network_state = {}
save_state = set()
MAX_TRESHOLD = 3
blocked_ips = set()

parser = argparse.ArgumentParser(description='NIDS')
parser.add_argument( '-s', '--source_email', required=True, help='Source email address to send the report')
parser.add_argument('-p', '--password', required=True, help='App password (app password gmail)')
parser.add_argument('-d', '--dest_email', required=True, help='Destination email address')
parser.add_argument('-i', '--interval', required=True, help='Time interval to send NIDS report')
dst_email = parser.parse_args().source_email
src_mail = parser.parse_args().dest_email
password = parser.parse_args().password
interval = parser.parse_args().interval


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

            to_log = to_block(src, network, tcp_layer.dport)
            if to_log >= 0:
                write_log(to_log, src, network, tcp_layer.dport, "SYN Scan")
                block_ip(src, to_log)


def to_block(src, network, port):
    global state, network_state, MAX_TRESHOLD

    # Check for a network scan
    if network is not None:
        if network not in network_state.keys():
            network_state[network] = set()
        ports = set()
        ports.add(port)
        for src_ip in network_state[network]:
            for elem in state[src_ip]:
                ports.add(elem)
        network_state[network].add(src)
        if len(ports) >= MAX_TRESHOLD and len(network_state[network]) >= 3:
            return 2

    # Check for a one ip scan
    if src in state.keys():
        return 1 if len(state[src]) >= MAX_TRESHOLD else -1
    else:
        return -1


def write_log(to_log, src, network, target, log_type):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open("log.txt", "a") as log_file:
        if to_log == 1:
            # Avoid multiple log
            if src in save_state:
                return
            log_file.write(f"{timestamp} {log_type}: {src} -> {target}\n")
            print(f"{timestamp} {log_type}: {src} -> {target}")
        elif to_log == 2:
            if network in save_state:
                return
            log_file.write(f"{timestamp} {log_type}: {network} -> {target}\n")
            print(f"{timestamp} {log_type}: {network} -> {target}")


def get_ports(content_type, content):
    global state, network_state
    if content_type == 0:
        return list(state[content])
    else:
        ports = []
        for ip_src in network_state[content]:
            ports += get_ports(0, ip_src)
        return ports


def encrypt_log():
    log_path = './log.txt'

    # Create new key
    primary_key = Fernet.generate_key()
    # store key
    if not os.path.exists('filekey.key'):
        with open('filekey.key', 'wb') as filekey:
            filekey.write(primary_key)
    with open('filekey.key', 'rb') as filekey:
        key = filekey.read()
    if len(key) != 32:
        with open('filekey.key', 'wb') as filekey:
            filekey.write(primary_key)
        with open('filekey.key', 'rb') as filekey:
            key = filekey.read()

    fernet = Fernet(key)

    with open(log_path, 'rb') as file:
        log_data = file.read()
    encrypted = fernet.encrypt(log_data)
    return encrypted


def send_log():
    global dst_email, src_mail, password, interval

    threading.Timer(int(interval), send_log).start()
    if not os.path.exists("log.txt"):
        return

    encrypted_log = encrypt_log().decode("utf-8")

    print("Sending log file...")

    recipients = [dst_email]
    msg = MIMEText(encrypted_log)
    msg["Subject"] = "NIDS report"
    msg["To"] = ", ".join(recipients)
    msg["From"] = src_mail
    smtp_server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    smtp_server.login(src_mail, password)
    smtp_server.sendmail(msg["From"], recipients, msg.as_string())
    smtp_server.quit()


def block_ip(ip_src, type):
    global save_state
    if type == 2:
        network = '.'.join(ip_src.split('.')[:-1]) + ".0/24"
        if network not in save_state:
            write_log(1, network, network, network, "Blocking")
            save_state.add(network)
            print(f"Blocking {'.'.join(ip_src.split('.')[:-1])}.0/24...")
            for i in range(1,255):
                ip = f"{'.'.join(ip_src.split('.')[:-1])}.{i}"
                subprocess.run(
                    ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                subprocess.run(
                    ['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                unblock_cmd = f"iptables -D INPUT -s {ip} -j DROP"
                unblock_out_cmd = f"iptables -D OUTPUT -d {ip} -j DROP"
                subprocess.run(
                    ['sudo', 'at', f'now + {1} hour'],
                    input=unblock_out_cmd.encode(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                subprocess.run(
                    ['sudo', 'at', f'now + {1} hour'],
                    input=unblock_cmd.encode(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
    else:
        if ip_src not in save_state:
            write_log(1, ip_src, ip_src, ip_src, "Blocking")
            save_state.add(ip_src)
            print(f"Blocking {ip_src}...")
            subprocess.run(
                ['sudo', 'iptables', '-A', 'INPUT', '-s', ip_src, '-j', 'DROP'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip_src, '-j', 'DROP'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            unblock_cmd = f"iptables -D INPUT -s {ip_src} -j DROP"
            unblock_out_cmd = f"iptables -D OUTPUT -d {ip_src} -j DROP"
            subprocess.run(
                ['sudo', 'at', f'now + {1} hour'],
                input=unblock_cmd.encode(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ['sudo', 'at', f'now + {1} hour'],
                input=unblock_out_cmd.encode(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )


send_log()
clear_state()
#if __name__ == '__main__':
    #send_log()
    #clear_state()
    #sniff(filter="tcp", iface="lo", prn=log_syn_packet, store=0)
