from netfilterqueue import NetfilterQueue
#import pyshark
import os
import sys
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapWriter, PcapWriter, PcapReader

from scapy.layers import *
import socket
import codecs
import re

#############################
# packet handling section 
#############################
#create a new file

def print_and_accept(pkt):
    _pkt = IP(pkt.get_payload())
    if _pkt.haslayer(TCP):
        print(_pkt.show())
    else:
        pass
    #print(pkt.lastlayer())
    pkt.accept()
    
print("start!")
load_layer("tls")
nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)


try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()
