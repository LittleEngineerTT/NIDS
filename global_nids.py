from scapy.all import sniff, TCP
from ssh_bruteforce import ssh_nids
from dos_scan import NdisDOS
from nids import nids

def global_detect(packet):
    # we redirect packet to every sub-nids and they will treat it as they want
    ssh_nids.detect_bruteforce(packet)
    nids.log_syn_packet(packet)
    NdisDOS.detect_syn_flood(packet)

print(f"Started Global NIDS Protection System...")
# we directly filter by port here!
sniff(filter=f"tcp", prn=global_detect, store=0, iface="lo")

