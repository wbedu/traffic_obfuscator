#!/usr/bin/env python3

import argparse
from scapy.all import (SniffSource, PipeEngine, get_if_list, Sink, IP, UDP, DNS,
                       DNSQR, DNSRR, send, TCP, UDP, Ether, get_if_addr, sniff)
import logging
import time
import csv

LOG = logging.getLogger("traffic obfuscator")
writer = csv.writer(open("traffic.csv",'a'), dialect='excel')


def store_data(pkt):
    timestamp = time.time()
    LOG.info(f"{timestamp} {pkt.getlayer(IP).src}:{pkt.getlayer(IP).sport} => {pkt.getlayer(IP).dst}:{pkt.getlayer(IP).dport}")
    writer.writerow([timestamp, pkt.getlayer(IP).src,pkt.getlayer(IP).sport, pkt.getlayer(IP).dst, pkt.getlayer(IP).dport])
if __name__ == "__main__":
    valid_interfaces = get_if_list()
    parser = argparse.ArgumentParser(conflict_handler="resolve")
    parser.add_argument("-i", "--interface",
        help="network device interface to sniff",
        default=valid_interfaces[1],
        required=False)
    parser.add_argument("-h", "--hostnames",
        help="""a hostname file containing a list of IP address
        and hostname pairs specifying the hostnames to be hijacked defaults to
        all hosts""",
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
    else:
        LOG.info(f"using interface: {args.interface}")
    SELF = get_if_addr(args.interface)

    while True:
        sniff(prn=store_data, iface=args.interface, filter="udp port 80 or tcp port 80 or udp port 443 or tcp port 443")