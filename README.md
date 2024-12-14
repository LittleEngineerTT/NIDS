# NIDS implementation 

A little project implementing NIDS to block DDOS, SYN scan, and ssh brute force attack.
To do it, we leverage on scapy a python library and 3 honeypot each is specialized on detecting 1 of these attack.  

## Prerequisites
 - **Python3** : Ensure you have Python3 installed on your device.
 - **Administrative Privileges**   : To add/remove `iptables` rules and use scapy, you must have Admin permissions.

## Start the project
### Launch the NIDS
For a full compatibility we encourage the use of gmail email as source email.
First ensure to create an app password to access your email box.
Be aware to enter the app password as a block without space if you are using google app password.
Ensure to have a *log.txt* file even if it is empty before executing the NIDS.

- Complete the .env variables
- Execute the NIDS by running ```docker compose up -d --build```


### Execute attacks
#### SYN port scan attack
- Go inside the container using `docker exec -ti CONTAINER_ID bash`
- Reach the /app/syn_scan directory
- To get help on what to do execute `sudo python3 syn_scan.py --help`

*NOTE: 2 variants have been implemented passing same_network or several arguments to the script*

#### SSH bruteforce attack
- Stay inside the container
- Reach the s/app/sh_bruteforce directory
- Execute `sudo python3 exploit.py`

#### layer 7 DOS attack
- Go outside the container
- Then, go inside the /app/dos_scan directory
- Execute `sudo python3 SynAtk.py`

*NOTE: After each execution of attack script you should see a new *iptables* rules appear blocking IP. 
To see it, run `sudo iptables -v -L -n`.*


### Logs
Logs are updated inside /app/log.txt file. Alternatively they are sent encrypted to the email specified in the .env file.


### Logs decryption
- If you use a mail app supporting GPG, you can decrypt the message directly inside your app otherwise you will have to use a pgp decryptor app.
