from scapy.all import *
import sys
import time


def scan_port(ip, port, timeout=1, src_ip=None):
    state = "closed"

    # Syn packet
    if src_ip:
        p = IP(src=src_ip ,dst=ip)/TCP(dport=port, flags='S')
    else:
        p = IP(dst=ip)/TCP(dport=port, flags='S')
    answers, un_answered = sr(p, timeout=0.2, verbose=False)  # Send the packets
    for req, resp in answers:
        if not resp.haslayer(TCP):
            continue
        tcp_layer = resp.getlayer(TCP)
        if tcp_layer.flags == 0x12:
            state = "open"

    print(f"{port} is {state}")
    time.sleep(timeout)
    return


def create_ip_list(number):
    ip_list = []
    for i in range(1, number + 1):
        ip_list.append("127.0.1." + str(i%254))
    return ip_list


def show_help():
    print("Usage: python syn_scan.py <ip> <ports> <scan_type>\n")
    print("ARGUMENTS:\n"
          "\tscan_type:\n" +
          "\t\tsimple: scan to a single port\n" +
          "\t\tseveral: scan to multiple ports using 3 seconds as delay\n"
          )
    print("\tports: list of ports to scan. Examples 1,2-10,11 OR 22")

if __name__ == "__main__":

    if len(sys.argv) != 3 and len(sys.argv) != 4 or "--help" in sys.argv or "-h" in sys.argv:
        show_help()
        sys.exit(1)

    target_ip = sys.argv[1]
    tmp_target_port = sys.argv[2]
    target_port = []
    scan_type = sys.argv[3] if len(sys.argv) == 4 else "simple"
    tmp_target_port = tmp_target_port.split(",")
    for elem in tmp_target_port:
        if '-' in elem:
            elem = elem.split('-')
            if len(elem) == 2:
                interval = [str(i) for i in range(int(elem[0]), int(elem[1]) + 1)]
                target_port += interval
        else:
            target_port.append(elem)

    print(f"Syn scan to {target_ip} on {target_port} port")

    if scan_type == "simple":
        if len(target_port) != 1:
            print("You should use a single port")
            show_help()
            sys.exit(1)
        scan_port(target_ip, int(target_port[0]), src_ip="127.0.1.3")

    elif scan_type == "several":
        for port in target_port:
            scan_port(target_ip, int(port), 3, src_ip="127.0.1.2")

    elif scan_type == "same_network":
        ip_list = create_ip_list(len(target_port))
        for i in range(len(target_port)):
            scan_port(target_ip, int(target_port[i]), 0, src_ip=ip_list[i])
    else:
        print("Error: Invalid scan type")
        show_help()