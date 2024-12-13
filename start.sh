#!/bin/bash
python3 syn_scan/port_scanner/portscanhoneypot.py -c syn_scan/port_scanner/pshp.conf &
su - cowrie -c "cd /cowrie/cowrie-git && . /cowrie/cowrie-env/bin/activate && /cowrie/cowrie-git/bin/cowrie start -n &"
sudo python3 global_nids.py --source_email $src_email --password $password --dest_email $dst_email -i $interval
