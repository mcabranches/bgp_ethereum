#!/bin/bash

echo "Killing any existing rogue AS"
./stop_rogue.sh

echo "Starting rogue AS"
sudo python run.py --node R4 --cmd "zebra -f /etc/quagga/zebra.conf -d -i /tmp/zebra-R4.pid"
sudo python run.py --node R4 --cmd "bgpd -f /etc/quagga/bgpd.conf -d -i /tmp/bgpd-R4.pid"
