#!/usr/bin/env python3
import requests as req
import json
import os
import random
from time import sleep
import logging

if __name__ == "__main__":
    host_file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),"hosts.json")
    hosts = None
    with open(host_file_path, "r") as file:
        hosts = json.load(file)
    logging.basicConfig()
    LOG = logging.getLogger("noisy")
    logging.getLogger().setLevel(logging.INFO)
    while True:
        host = random.choice(hosts)
        LOG.info(f"GET {host}")
        req.get(host)
        sleep(random.uniform(0, 2))

