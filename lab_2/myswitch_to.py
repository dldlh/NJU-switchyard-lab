'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time
class learning(object):
    def __init__(self,mac,interface,time):
        self.mac = mac
        self.interface = interface
        self.time = time

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    table =[]
    flag = 0 
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return
        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            nowtime = time.time()
            for index in table:
                if nowtime - index.time > 10:
                    table.remove(index)
                if index.mac == packet[0].src:
                    table.remove(index)
        
            temp = learning(packet[0].src,input_port,nowtime)
            table.append(temp)
        
            flag = 0
            for index in table:
                if index.mac == packet[0].dst:
                   flag = 1
                   destintf = index.interface
                   break
            if flag == 1:
                net.send_packet(destintf, packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
