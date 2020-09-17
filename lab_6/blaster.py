#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import time


class waititem(object):
    def __init__(self,pkt,istimeout:bool,isresend:bool,seq):
        self.pkt = pkt
        self.istimeout = istimeout
        self.isresend = isresend
        self.seq = seq

def createpkt(payloadlength,seq):
    
    blasteemac = '20:00:00:00:00:01'
    blastermac = '10:00:00:00:00:01'
    blasteeip = '192.168.200.1'
    blasterip = '192.168.100.1'
    
    pkt = Ethernet(src = blastermac,dst = blasteemac , ethertype = EtherType.IPv4) + IPv4(src = blasterip, dst = blasteeip , protocol = IPProtocol.UDP,ttl = 8) + UDP(src = 1,dst = 2)
    pkt31 = RawPacketContents(seq.to_bytes(4,byteorder = 'big'))
    pkt32 = RawPacketContents(payloadlength.to_bytes(2,byteorder = 'big'))
    pkt4 = RawPacketContents(seq.to_bytes(payloadlength,byteorder = 'big'))
    pkt += pkt31
    pkt += pkt32
    pkt += pkt4
    return pkt

def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    fp = open('blaster_params.txt','r')
    filelist = []
    line = fp.readline()
    filelist = line.split()
    num = int(filelist[3])
    blasteeip = str(filelist[1])   
    payloadlength = int(filelist[5])
    swsize = int(filelist[7])
    timeout_time = float(filelist[9])
    timeout_time = timeout_time / 1000
    recv_time = float(filelist[11])
    recv_time = recv_time / 1000

    rhs = 1
    lhs = 1
    starttime = time.time()
    recnt = 0
    timeoutcnt = 0
    allbytes = 0
    usebytes = 0
    waitacklist = []
    lhstime = time.time()
    
    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            timestamp,dev,pkt = net.recv_packet(timeout = recv_time)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break
        #debugger()
        if time.time() - lhstime > timeout_time:
            timeoutcnt += 1
            lhstime = time.time()
            for index in waitacklist:
                index.istimeout = True
                index.isresend = False
        
        if gotpkt:
            #debugger()
            log_debug("I got a packet")
            prelhs = lhs
            temp1 = pkt[3].to_bytes()[:4]
            seqencenumber = int.from_bytes(temp1,byteorder = 'big')
            for index in waitacklist:
                if index.seq == seqencenumber:
                    waitacklist.remove(index)
                    break
            if len(waitacklist) == 0:
                lhs = rhs
                if lhs >= num:
                    alltime = time.time()-starttime
                    log_info("total tx time:{}\n".format(alltime))
                    log_info("number of retx:{}\n".format(recnt))
                    log_info("number of coarse tos:{}\n".format(timeoutcnt))
                    log_info("throughput: {}\n".format(allbytes/alltime))
                    log_info("goodput: {}\n".format(usebytes/alltime))
                    break
            else:    
                lhs = num + 1
                for index in waitacklist:
                    if index.seq < lhs:
                        lhs = index.seq
            if lhs != prelhs:
                lhstime = time.time()
            for index in waitacklist:
                if index.isresend == False and index.istimeout == True:
                    net.send_packet(my_intf[0].name,index.pkt)
                    allbytes += payloadlength
                    index.isresend = True
                    recnt += 1
                    break
        
        else:
            log_debug("Didn't receive anything")
            
            flag = 1
            for index in waitacklist:
                if index.isresend == False and index.istimeout == True:
                    #log_info("resend a packet:{}".format(index.seq))
                    net.send_packet(my_intf[0].name,index.pkt)
                    allbytes += payloadlength
                    index.isresend = True
                    flag = 0
                    recnt += 1
                    break
            if flag == 0: #sended a packet
                continue
            
            if rhs - lhs + 1 <= swsize and rhs <= num:
                sendpkt = createpkt(payloadlength,rhs)
                #log_info("send a packet{}".format(rhs))
                net.send_packet(my_intf[0].name,sendpkt)
                usebytes += payloadlength
                allbytes += payloadlength
                temp = waititem(sendpkt,False,False,rhs)
                waitacklist.append(temp)
                rhs += 1


    net.shutdown()
