'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *

class learning(object):
    def __init__(self,mac,interface,age):
        self.mac = mac
        self.interface = interface
        self.age = age

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    table = []
    flag = 0
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return
        flag = 0
        for index in table:
            if index.mac == packet[0].dst:
                flag = 1
                destintf = index.interface
                index.age = 0
            else:
                index.age = index.age + 1
        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            if flag == 1:
                 net.send_packet(destintf, packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
        temp = learning(packet[0].src,input_port,0)

        for index in table:
            if index.mac == packet[0].src:
                table.remove(index)
        if len(table) >= 5:
            table.remove(max(table,key = lambda x: x.age))

        table.append(temp)
    net.shutdown()
