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


    def createicmperror(self,origpkt,errortype,srcip,dstip):
        i = origpkt.get_header_index(Ethernet)
        del origpkt[i]
        icmp = ICMP()
        if errortype == 1:
             icmp.icmptype = ICMPType.DestinationUnreachable
             icmp.icmpcode = ICMPTypeCodeMap[icmp.icmptype].NetworkUnreachable
        elif errortype == 2:
            icmp.icmptype = ICMPType.TimeExceeded
            icmp.icmpcode = ICMPTypeCodeMap[icmp.icmptype].TTLExpired
        elif errortype == 3:
            icmp.icmptype = ICMPType.DestinationUnreachable
            icmp.icmpcode = ICMPTypeCodeMap[icmp.icmptype].HostUnreachable
        elif errortype == 4:
            icmp.icmptype = ICMPType.DestinationUnreachable
            icmp.icmpcode = ICMPTypeCodeMap[icmp.icmptype].PortUnreachable
        icmp.icmpdata.data = origpkt.to_bytes()[:28]
        icmp.icmpdata.origdgramlen = len(origpkt)
        str(icmp)
        ip = IPv4()
        ip.protocol = IPProtocol.ICMP
        ip.ttl = 32
        ip.src = srcip
        ip.dst = dstip 
        e = Ethernet()
        pkt = e + ip + icmp
        return pkt


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
                    #for index2 in arptable:
                        #log_info("ip: {}\tmac:{}\n".format(str(index2.ip),str(index2.mac)))
                    
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
                    error = 0
                    maxlength = 0
                    for intf in intftable:
                        if intf.ipaddr == ipv4.dst:
                            flag = 0
                            srcmac = intf.ethaddr
                            break
                    if flag == 0:
                        icmp = pkt.get_header(ICMP)
                        if icmp is not None:
                            if icmp.icmptype == ICMPType.EchoRequest:
                                i = ICMP(icmptype = ICMPType.EchoReply, data = icmp.icmpdata.data,sequence = icmp.icmpdata.sequence,identifier = icmp.icmpdata.identifier)
                                ipheader = IPv4(src= ipv4.dst,dst = ipv4.src,ttl = 32)
                                e = Ethernet(src = srcmac)
                                sendpkt = e + ipheader + i
                                pkt = sendpkt
                                ipv4 = ipheader
                                flag = 1
                        
                        #not icmp request
                        if flag == 0:
                            flag = 1
                            maxlength = 0
                            for index in forwardingtable:
                                #debugger()
                                matches = ipv4.src in index.prefixnet
                                if matches == True:
                                    if index.prefixnet.prefixlen > maxlength:
                                        maxlength = index.prefixnet.prefixlen
                                        dest = index
                                        flag = 0
                            if flag == 0:
                                self.port = self.net.interface_by_name(dest.intfname)
                                pkt = self.createicmperror(pkt,4,port.ipaddr,ipv4.src)
                                ipv4 = pkt.get_header(IPv4)
                                error = 1
                    
                    if error == 0:
                        flag = 1
                        for index in forwardingtable:
                            #debugger()
                            matches = ipv4.dst in index.prefixnet
                            if matches == True:
                                if index.prefixnet.prefixlen > maxlength:
                                    maxlength = index.prefixnet.prefixlen
                                    dest = index
                                    flag = 0                    
                    
                    # matched
                    if flag == 0:
                        if pkt[IPv4].ttl == 0:
                            pkt[IPv4].ttl = 1
                            flag = 1
                            maxlength = 0
                            #debugger()
                            for index in forwardingtable:
                                #debugger()
                                matches = ipv4.src in index.prefixnet
                                if matches == True:
                                    if index.prefixnet.prefixlen > maxlength:
                                        maxlength = index.prefixnet.prefixlen
                                        dest = index
                                        flag = 0
                            #debugger()
                            if flag == 0:
                                port = self.net.interface_by_name(dest.intfname)
                                pkt= self.createicmperror(pkt,2,port.ipaddr,ipv4.src)
                                ipv4 = pkt.get_header(IPv4)
                                #debugger()
                    
                    # not match
                    else:
                        flag = 1
                        maxlength = 0
                        for index in forwardingtable:
                            #debugger()
                            matches = ipv4.src in index.prefixnet
                            if matches == True:
                                if index.prefixnet.prefixlen > maxlength:
                                    maxlength = index.prefixnet.prefixlen
                                    dest = index
                                    flag = 0
                        if flag == 0:
                            self.port = self.net.interface_by_name(dest.intfname)
                            pkt = self.createicmperror(pkt,1,port.ipaddr,ipv4.src)
                            ipv4 = pkt.get_header(IPv4)
                    
                    port = self.net.interface_by_name(dest.intfname)
                    if dest.nextip is None:
                        nextip = ipv4.dst
                    else:
                        nextip = dest.nextip
                    pkt[Ethernet].src = port.ethaddr
                    #debugger()
                    
                    flag = 1
                    for searchindex in arptable:
                        if str(searchindex.ip) == str(nextip):
                            pkt[0].dst = searchindex.mac
                            self.net.send_packet(dest.intfname,pkt)
                            flag = 0
                            break            
                        
                    if flag == 1:
                        #debugger()
                        sendtemp = queueitem(pkt,pretime - 1,nextip,1,dest.intfname)
                        sendqueue.append(sendtemp)
            
            #debugger()
            if len(sendqueue) != 0 :
                nowtime = time.time()
                for index in sendqueue:
                    if index.cnt > 5:
                        #debugger()
                        pkt = index.pkt
                        ipv4 = pkt.get_header(IPv4)
                        flag = 1
                        maxlength = 0
                        for index2 in forwardingtable:
                            #debugger()
                            matches = ipv4.src in index2.prefixnet
                            if matches == True:
                                if index2.prefixnet.prefixlen > maxlength:
                                    maxlength = index2.prefixnet.prefixlen
                                    dest = index2
                                    flag = 0
                        #debugger()
                        if flag == 0:
                            port = self.net.interface_by_name(dest.intfname)
                            pkt = self.createicmperror(pkt,3,port.ipaddr,ipv4.src)
                            ipv4 = pkt.get_header(IPv4)
                        #debugger()

                        port = self.net.interface_by_name(dest.intfname)
                        if dest.nextip is None:
                            nextip = ipv4.dst
                        else:
                            nextip = dest.nextip
                        pkt[Ethernet].src = port.ethaddr
                        #debugger()

                        flag = 1
                        for searchindex in arptable:
                            if str(searchindex.ip) == str(nextip):
                                pkt[0].dst = searchindex.mac
                                self.net.send_packet(dest.intfname,pkt)
                                flag = 0
                                break            
                        
                        if flag == 1:
                            #debugger()
                            sendtemp = queueitem(pkt,nowtime - 1,nextip,1,dest.intfname)
                            sendqueue.append(sendtemp)
                        sendqueue.remove(index)
                        index = sendtemp

                    #debugger()
                    
                    if nowtime - index.time >= 1:
                        flag = 1
                        for index3 in arpwait:
                            if index3.ipaddr == nextip:
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
