# NDIS implementation 

A little project implementing NDIS to block DDOS, SYN scan, and ssh brute force attack.
To do it, we leverage on scapy a python library and 3 honeypot each is specialized on detecting 1 of these attack.  

### SYN scan attack
First of all we need a target so we used PortScanHoneypot as SYN scan honeypot.
- Go to the (https://github.com/DanaEpp/PortScanHoneypot) and follow the installation guide.
- Go inside ./syn_scan/ dir
- Configure the honeypot in ./pshp.conf
- Install dependencies `pip3 install -r requirements.txt`
- Run the honeypot using `sudo python3 portscanhoneypot.py -c pshp.conf`
- Execute the attacker script and see SYN scan logs appear on monitored ports.
