import socket
import time
import sys


def scan_port(ip: str, port: int, delay:int = 0):
    try:
        # socket creation
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        # Connection
        result = sock.connect_ex((ip, port))

        if result == 0:
            print(f"The {port} is open")
        else:
            print(f"The {port} is closed")

    except socket.error:
        print(f"Socket connection error")
    finally:
        sock.close()

    time.sleep(delay)

def show_help():
    print("Usage: python script.py <ip> <ports> <scan_type>\n")
    print("ARGUMENTS:\n"
          "\tscan_type:\n" +
          "\t\tsimple: scan to a single port\n" +
          "\t\tsev_unmon: scan multiple ports once\n" +
          "\t\tsev_unmon_delay: sev_unmon using 0.5 seconds as delay\n" +
          "\t\tsev_unmon_bigdelay: sev_unmon using 3 seconds as delay\n"
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
        scan_port(target_ip, int(target_port))
    elif scan_type == "sev_unmon":
        for port in target_port:
            scan_port(target_ip, int(port))
    elif scan_type == "sev_unmon_delay":
        for port in target_port:
            scan_port(target_ip, int(port), 0.5)
    elif scan_type == "sev_unmon_bigdelay":
        for port in target_port:
            scan_port(target_ip, int(port), 3)
    #elif scan_type == "sev_unmon_bigdelay":
