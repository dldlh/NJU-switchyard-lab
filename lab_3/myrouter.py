#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *

class arpitem(object):
    def __init__(self,ip ,mac):
        self.ip = ip
        self.mac = mac


class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        arptable = []
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                arp = pkt.get_header(Arp)
                if arp is not None:
                    intftable = self.net.interfaces()
                    for index in intftable:
                        if index.ipaddr == arp.targetprotoaddr:
                            packet = create_ip_arp_reply(index.ethaddr,arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr)
                            # packet = create_ip_arp_reply(arp.senderhwaddr,index.ethaddr,arp.senderprotoaddr,arp.targetprotoaddr)
                            self.net.send_packet(dev,packet)
                    
                    flag = 0
                    for index in arptable:
                        if index.ip == arp.senderprotoaddr and index.mac != arp.senderhwaddr:
                            arptable.remove(index) #item is changed
                        elif index.ip == arp.senderprotoaddr and index.mac == arp.senderhwaddr:
                            flag = 1 
                            break
                    if flag == 0:
                        temp = arpitem(arp.senderprotoaddr,arp.senderhwaddr)
                        arptable.append(temp)
                    for index2 in arptable:
                        log_info("ip: {}\tmac:{}\n".format(str(index2.ip),str(index2.mac)))









def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
