# NDIS implementation 

A little project implementing NDIS to block DDOS, SYN scan, and ssh brute force attack.
To do it, we leverage on scapy a python library and 3 honeypot each is specialized on detecting 1 of these attack.  

### NDIS
For a full compatibility we encourage the use of gmail email as source email.
First ensure to create an app password to access your email box.
Be aware to enter the app password as a block without space if you are using google app password.

- Go to ndis directory 
- Complete the .env
- Execute the NDIS by running ```docker compose up -d --build```
    