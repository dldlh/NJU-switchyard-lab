from switchyard.lib.userlib import *
import time
import re
from random import randint
class ruleitem(object):
    def __init__(self):
        self.rulenum = 0
        self.permit = True
        self.src = IPv4Network('0.0.0.0/0',False)
        self.types = 'ip'
        self.dst = IPv4Network('0.0.0.0/0',False)
        self.srcport = -1
        self.dstport = -1
        self.ratelimit = 0
        self.tokens = 0
        self.impair = False


def readrule(line):
    #debugger()
    rule = ruleitem()
    result = re.match(r'^#.*',line)
    if result:
        return None

    result = re.match(r'(permit|deny) (ip|icmp) src (\S+) dst (\S+) impair',line)
    if result:
        rule.rulenum = 0
        if result.group(1) == 'permit':
            rule.permit = True
        else:
            rule.permit = False
        if result.group(2) == 'icmp':
            rule.types = 'icmp'
        else:
            rule.types = 'ip'
        if result.group(3) == 'any':
            rule.src = IPv4Network('0.0.0.0/0',False)
        else:
            rule.src = IPv4Network(result.group(3),False)
        if result.group(4) == 'any':
            rule.dst = IPv4Network('0.0.0.0/0',False)
        else:
            rule.dst = IPv4Network(result.group(4),False)
        rule.ratelimit = 0
        rule.impair = True
        return rule  

    result = re.match(r'(permit|deny) (ip|icmp) src (\S+) dst (\S+) ratelimit (\S+)',line)
    if result:
        rule.rulenum = 0
        if result.group(1) == 'permit':
            rule.permit = True
        else:
            rule.permit = False
        if result.group(2) == 'icmp':
            rule.types = 'icmp'
        else:
            rule.types = 'ip'
        if result.group(3) == 'any':
            rule.src = IPv4Network('0.0.0.0/0',False)
        else:
            rule.src = IPv4Network(result.group(3),False)
        if result.group(4) == 'any':
            rule.dst = IPv4Network('0.0.0.0/0',False)
        else:
            rule.dst = IPv4Network(result.group(4),False)
        rule.ratelimit = int(result.group(5))
        rule.tokens = 2*rule.ratelimit
        rule.impair = False
        return rule    

    result = re.match(r'(permit|deny) (udp|tcp) src (\S+) srcport (\S+) dst (\S+) dstport (\S+) ratelimit (\S+)',line)
    if result:
        rule.rulenum = 1
        if result.group(1) == 'permit':
            rule.permit = True
        else:
            rule.permit = False
        if result.group(2) == 'tcp':
            rule.types = 'tcp'
        else:
            rule.types = 'udp'
        if result.group(3) == 'any':
            rule.src = IPv4Network('0.0.0.0/0',False)
        else:
            rule.src = IPv4Network(result.group(3),False)
        if result.group(5) == 'any':
            rule.dst = IPv4Network('0.0.0.0/0',False)
        else:
            rule.dst = IPv4Network(result.group(5),False)
        if result.group(4) == 'any':
            rule.srcport = -1
        else:
            rule.srcport = int(result.group(4))
        if result.group(6) == 'any':
            rule.dstport = -1
        else:
            rule.dstport = int(result.group(6))
        rule.ratelimit = int(result.group(7))
        rule.tokens = 2*rule.ratelimit
        rule.impair = False
        return rule    

    result = re.match(r'(permit|deny) (ip|icmp) src (\S+) dst (\S+)',line)
    if result:
        rule.rulenum = 0
        if result.group(1) == 'permit':
            rule.permit = True
        else:
            rule.permit = False
        if result.group(2) == 'icmp':
            rule.types = 'icmp'
        else:
            rule.types = 'ip'
        if result.group(3) == 'any':
            rule.src = IPv4Network('0.0.0.0/0',False)
        else:
            rule.src = IPv4Network(result.group(3),False)
        if result.group(4) == 'any':
            rule.dst = IPv4Network('0.0.0.0/0',False)
        else:
            rule.dst = IPv4Network(result.group(4),False)
        rule.ratelimit = 0
        rule.impair = False
        return rule

    result = re.match(r'(permit|deny) (udp|tcp) src (\S+) srcport (\S+) dst (\S+) dstport (\S+) impair',line)
    if result:
        rule.rulenum = 1
        if result.group(1) == 'permit':
            rule.permit = True
        else:
            rule.permit = False
        if result.group(2) == 'tcp':
            rule.types = 'tcp'
        else:
            rule.types = 'udp'
        if result.group(3) == 'any':
            rule.src = IPv4Network('0.0.0.0/0',False)
        else:
            rule.src = IPv4Network(result.group(3),False)
        if result.group(5) == 'any':
            rule.dst = IPv4Network('0.0.0.0/0',False)
        else:
            rule.dst = IPv4Network(result.group(5),False)
        if result.group(4) == 'any':
            rule.srcport = -1
        else:
            rule.srcport = int(result.group(4))
        if result.group(6) == 'any':
            rule.dstport = -1
        else:
            rule.dstport = int(result.group(6))
        rule.ratelimit = 0
        rule.impair = True
        return rule    

    result = re.match(r'(permit|deny) (udp|tcp) src (\S+) srcport (\S+) dst (\S+) dstport (\S+)',line)
    if result:
        rule.rulenum = 1
        if result.group(1) == 'permit':
            rule.permit = True
        else:
            rule.permit = False
        if result.group(2) == 'tcp':
            rule.types = 'tcp'
        else:
            rule.types = 'udp'
        if result.group(3) == 'any':
            rule.src = IPv4Network('0.0.0.0/0',False)
        else:
            rule.src = IPv4Network(result.group(3),False)
        if result.group(5) == 'any':
            rule.dst = IPv4Network('0.0.0.0/0',False)
        else:
            rule.dst = IPv4Network(result.group(5),False)
        if result.group(4) == 'any':
            rule.srcport = -1
        else:
            rule.srcport = int(result.group(4))
        if result.group(6) == 'any':
            rule.dstport = -1
        else:
            rule.dstport = int(result.group(6))
        rule.ratelimit = 0
        rule.impair = False
        return rule    

    return None

def pktmatch(pkt,rules):
    ipv4 = pkt.get_header(IPv4)
    #debugger()
    icmp = pkt.get_header(ICMP)
    tcp = pkt.get_header(TCP)
    udp = pkt.get_header(UDP)
    pkttype = 'ip'
    if icmp is not None:
        pkttype = 'icmp'
    elif tcp is not None:
        pkttype = 'tcp'
    elif udp is not None:
        pkttype = 'udp'
    if pkttype == 'ip':
        return None
    
    for index in rules:
        #debugger()
        if index.types != 'ip' and index.types != pkttype:
            continue
        if ipv4.src in index.src and ipv4.dst in index.dst:
            if pkttype == 'icmp':
                return index
            elif pkttype == 'tcp':
                if (tcp.src == index.srcport or index.srcport == -1) and (tcp.dst == index.dstport or index.dstport == -1):
                    return index
            elif pkttype == 'udp':
                if (udp.src == index.srcport or index.srcport == -1) and (udp.dst == index.dstport or index.dstport == -1):
                    return index

    return None


def main(net):
    # assumes that there are exactly 2 ports
    portnames = [ p.name for p in net.ports() ]
    portpair = dict(zip(portnames, portnames[::-1]))
    rules = []
    fp = open('firewall_rules.txt','r')
    for line in fp.readlines():
        rule = readrule(line)
        if rule is not None:
            rules.append(rule)
    fp.close()
    #debugger()
    pretime = time.time()
    while True:
        pkt = None
        try:
            timestamp,input_port,pkt = net.recv_packet(timeout=0.25)
        except NoPackets:
            pass
        except Shutdown:
            break
        
        if time.time()-pretime > 0.5:
            for index in rules:
                if index.ratelimit != 0:
                    index.tokens = index.tokens + index.ratelimit/2
                    if index.tokens > 2*index.ratelimit:
                        index.tokens = 2*index.ratelimit
            pretime = time.time()

        if pkt is not None:
            ip = pkt.get_header(IPv4)
            if ip is None:
                net.send_packet(portpair[input_port], pkt)
                continue
      
            matchrule = pktmatch(pkt,rules)
            #debugger()
            if matchrule is None:
                net.send_packet(portpair[input_port], pkt)
                continue
            
            if matchrule.permit == True:
                for index in rules:
                    if index == matchrule:
                        if index.ratelimit != 0:
                            l = len(pkt) - len(pkt.get_header(Ethernet))
                            if index.tokens >= l:
                                index.tokens = index.tokens - l
                                net.send_packet(portpair[input_port], pkt)
                            break
                        if index.impair:
                            ran = randint(0,1)
                            #if ran > 0.5:
                            if ran > 2:
                                net.send_packet(portpair[input_port], pkt)
                            break
                        net.send_packet(portpair[input_port], pkt)
                        break

    net.shutdown()
