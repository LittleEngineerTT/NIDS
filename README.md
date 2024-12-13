# NDIS implementation 

A little project implementing NDIS to block DDOS, SYN scan, and ssh brute force attack.
To do it, we leverage on scapy a python library and 3 honeypot each is specialized on detecting 1 of these attack.  

## Prerequisites
 - **Python3** : Ensure you have Python3 installed on your device.
 - **Administrative Privileges**   : To add/remove `iptables` rules and use scapy, you must have Admin permissions.

### NDIS
For a full compatibility we encourage the use of gmail email as source email.
First ensure to create an app password to access your email box.
Be aware to enter the app password as a block without space if you are using google app password.
Ensure to have a filekey.key file even if it is empty before executing the NIDS to get the project working.

- Go to ndis directory 
- Complete the .env
- Execute the NDIS by running ```docker compose up -d --build```
- Use the decrypt.py script to decrypt log
- Store the mail content inside a file (example: encrypted_mail.txt)
- ```python3 decrypt.py -k filekey.key -f encrypted_mail.txt -o clear_mail.txt``` 
