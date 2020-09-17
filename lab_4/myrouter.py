#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
import re
from switchyard.lib.address import * 
from switchyard.lib.userlib import *

class arpitem(object):
    def __init__(self,ip ,mac):
        self.ip = ip
        self.mac = mac

class forwardingitem(object):
    def __init__(self,netaddr,subnet_mask,nextip,intfname,prefixnet):
        self.netaddr = netaddr
        self.subnet_mask = subnet_mask
        self.nextip = nextip
        self.intfname = intfname
        self.prefixnet = prefixnet

class queueitem(object):
    def __init__(self,pkt,time,dstip,cnt,intfname):
        self.pkt = pkt
        self.time = time
        self.dstip = dstip
        self.cnt = cnt
        self.intfname = intfname


class arpwaititem(object):
    def __init__(self,ipaddr,time):
        self.ipaddr = ipaddr
        self.time = time        
class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        intftable = self.net.interfaces()
        myip = [intf.ipaddr for intf in intftable]
        arptable = []
        arpwait = []
        forwardingtable = []
        fp = open('forwarding_table.txt','r')
        sendqueue = []
        
        for line in fp.readlines():
            if len(line) > 10:
                item1,item2,item3,item4 = line.split()
                prefixnet = IPv4Network('{}/{}'.format(item1,item2))
                fwtemp = forwardingitem(item1,item2,item3,item4,prefixnet)
                #debugger()
                forwardingtable.append(fwtemp)
        
        fp.close()
        for intf in intftable:
            prefixnet = IPv4Network('{}/{}'.format(intf.ipaddr,intf.netmask),False)
            fwtemp = forwardingitem(intf.ipaddr,intf.netmask,None,intf.name,prefixnet)
            forwardingtable.append(fwtemp)
        
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
            
            
            nowtime = time.time()
            for index in arpwait:
                if nowtime - index.time > 1:
                    arpwait.remove(index)
            
            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                arp = pkt.get_header(Arp)
                ipv4 = pkt.get_header(IPv4)
                if arp is not None:
                    if arp.operation == 1:
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
                    
                    for queueindex in sendqueue:
                        #debugger()
                        if str(arp.senderprotoaddr) == str(queueindex.dstip):
                            queueindex.pkt[0].dst = arp.senderhwaddr
                            self.net.send_packet(dev, queueindex.pkt)
                            sendqueue.remove(queueindex)

                    for index in arpwait:
                        if str(index.ipaddr) == str(arp.senderprotoaddr):
                            arpwait.remove(index)                

                if ipv4 is not None:
                    #debugger()
                    pkt[IPv4].ttl -= 1
                    pretime = time.time()
                    #debugger()
                    flag = 1
                    maxlength = 0
                    for index in forwardingtable:
                        #debugger()
                        matches = ipv4.dst in index.prefixnet
                        if matches == True:
                            if index.prefixnet.prefixlen > maxlength:
                                maxlength = index.prefixnet.prefixlen
                                dest = index
                                flag = 0                    
                    
                    if flag == 0:
                        port = self.net.interface_by_name(dest.intfname)
                        if dest.nextip is None:
                            dest.nextip = ipv4.dst
                        pkt[Ethernet].src = port.ethaddr
                        #debugger()
                        
                        flag = 1
                        for searchindex in arptable:
                            if searchindex.ip == dest.nextip:
                                pkt[0].dst = searchindex.mac
                                self.net.send_packet(dest.intfname,pkt)
                                flag = 0
                                break            
                        
                        if flag == 1:
                            #debugger()
                            sendtemp = queueitem(pkt,pretime - 1,dest.nextip,1,dest.intfname)
                            sendqueue.append(sendtemp)     
            
            #debugger()
            if len(sendqueue) != 0 :
                nowtime = time.time()
                for index in sendqueue:
                    if index.cnt > 5:
                        sendqueue.remove(index)
                        continue
                    
                    #debugger()
                    
                    if nowtime - index.time > 1:
                        flag = 1
                        for index in arpwait:
                            if index.ipaddr == dest.nextip:
                                flag = 0
                                break
                        if flag == 1:
                        #if index.dstip not in arpwait:
                            self.port = self.net.interface_by_name(index.intfname)
                            arppkt = create_ip_arp_request(port.ethaddr,port.ipaddr,index.dstip)
                            #debugger()
                            self.net.send_packet(index.intfname,arppkt)
                            index.cnt = index.cnt + 1
                            temp = arpwaititem(index.dstip,nowtime)
                            arpwait.append(temp)
                    index.time = nowtime                                          

                    

                    

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
