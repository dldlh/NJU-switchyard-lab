#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time




def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    fp = open('blastee_params.txt','r')
    line = fp.readline()
    blasterip = str(line.split()[1])
    blastermac = '10:00:00:00:00:01'
    blasterip = '192.168.100.1'

    while True:
        gotpkt = True
        try:
            timestamp,dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            #debugger()
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))
            ipv4 = pkt.get_header(IPv4)
            mymac = mymacs[0]
            myip = '192.168.200.1'
            if ipv4 is None:
                continue
            if str(ipv4.src) != str(blasterip):
                continue 
            temp1 = pkt[3].to_bytes()[:4]
            temp2 = pkt[3].to_bytes()[4:6]
            seqencenumber = int.from_bytes(temp1,byteorder = 'big')
            payloadlength = int.from_bytes(temp2,byteorder = 'big')
            if payloadlength > 8:
                payloadlength = 8
            #debugger()
            
            #payload = pkt[4].to_bytes()[:len(pkt[4])]
            payload = pkt[3].to_bytes()[6: 6 + payloadlength]
            while payloadlength < 8:
                payload += b' '
                payloadlength += 1
            
            seq = RawPacketContents(seqencenumber.to_bytes(4,byteorder = 'big'))
            pay = RawPacketContents(payload)
            e = Ethernet(src = mymac,dst = blastermac)
            ip = IPv4(src = myip,dst = blasterip ,protocol = IPProtocol.UDP,ttl = 8)
            udp = UDP(src = 2,dst = 1)
            sendpkt = e + ip + udp + seq + pay
            net.send_packet(dev, sendpkt)
    
    net.shutdown()
