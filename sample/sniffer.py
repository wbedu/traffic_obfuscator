#!/usr/bin/env python3

import argparse
from scapy.all import (get_if_list, sniff, IP)
import logging
from time import time

LOG = logging.getLogger("sniffer")
fh = logging.FileHandler('sniffer.log', mode='w', encoding='utf-8')
fh.setLevel(logging.INFO)
fh.setFormatter(logging.Formatter('%(message)s'))
LOG.addHandler(fh)

def store_data(pkt):
    timestamp = time()
    LOG.info(f"{timestamp},{pkt.getlayer(IP).src},{pkt.getlayer(IP).sport},{pkt.getlayer(IP).dst},{pkt.getlayer(IP).dport}")
if __name__ == "__main__":
    valid_interfaces = get_if_list()
    parser = argparse.ArgumentParser(conflict_handler="resolve")
    parser.add_argument("-i", "--interface",
        help="network device interface to sniff",
        default=valid_interfaces[1],
        required=False)
    parser.add_argument("-v","--verbose",
        help="verbosity level",
        action='count',
        default=0,
        required=False)
    args = parser.parse_args()


    logging.basicConfig()
    logging.getLogger().setLevel(logging.WARN - 10 * args.verbose)

    if not args.interface or args.interface not in get_if_list():
        LOG.error(f"{args.interface} is not an available interface.")
        raise Exception(f"{args.interface} is not an available interface.")
    
    sniff(prn=store_data, iface=args.interface, filter="udp port 80 or tcp port 80 or udp port 443 or tcp port 443")