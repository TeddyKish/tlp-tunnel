# Libraries
import argparse
import threading
from abc import ABCMeta, abstractmethod
from netfilterqueue import NetfilterQueue
from scapy.all import *

# Constants
DEF_OUTBOUND_QUEUENUM = 2
DEF_INBOUND_QUEUENUM  =  3

ICMP_PING_PAYLOAD_SUFFIX = "01234567"
ICMP_ECHO_REQUEST_ID = 8
ICMP_ECHO_REPLY_ID   = 0

# Classes
class TunnelBaseProtocol(object):
    """
    Represents the base protocol, over which the tunneling occurs (i.e. ICMP, DNS etc..).
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def transform_outbound(self, tunneled_packet_bytes):
        pass

    @abstractmethod
    def transform_inbound(self, original_packet_bytes):
        pass

class ICMPBase(TunnelBaseProtocol):
    """
    Represents ICMP as the base protocol.
    """
    def __init__(self, is_requester):
        if is_requester:
            self.outbound_icmp_message_type = ICMP_ECHO_REQUEST_ID
            self.inbound_icmp_message_type  = ICMP_ECHO_REPLY_ID
        else:
            self.outbound_icmp_message_type = ICMP_ECHO_REPLY_ID
            self.inbound_icmp_message_type  = ICMP_ECHO_REQUEST_ID

    def transform_outbound(self, tunneled_packet_bytes):
        tunneled_packet = IP(tunneled_packet_bytes)

        # Packet initialization
        icmp_packet = IP() / ICMP()
        icmp_packet[ICMP].type = self.outbound_icmp_message_type
        icmp_packet[ICMP].payload = Raw(tunneled_packet_bytes)
        icmp_packet[ICMP].chksum = None
        icmp_packet[IP].chksum = None
        icmp_packet[IP].len = None

        # Use original addressing values
        icmp_packet[IP].src = tunneled_packet[IP].src
        icmp_packet[IP].dst = tunneled_packet[IP].dst

        intermediary_packet = IP(bytes(icmp_packet))
        return raw(intermediary_packet)

    def transform_inbound(self, original_packet_bytes):
        icmp_packet = IP(original_packet_bytes)
    
        if icmp_packet[ICMP].type == self.inbound_icmp_message_type and icmp_packet[Raw].load[-8:] != ICMP_PING_PAYLOAD_SUFFIX:
            return icmp_packet[Raw].load
        return original_packet_bytes

# Functions
def outbound_nfqueue(queue_num):
    print("Started listening for outbound packets...")
    nfqueue = NetfilterQueue()
    nfqueue.bind(DEF_OUTBOUND_QUEUENUM, handle_outbound)

    try:
        nfqueue.run()
    except Exception as e:
        print(e.message)

    nfqueue.unbind()

def inbound_nfqueue(queue_num):
    print("Started listening for inbound packets...")
    nfqueue = NetfilterQueue()
    nfqueue.bind(DEF_INBOUND_QUEUENUM, handle_inbound)
    try:
        nfqueue.run()    
    except Exception as e:
        print(e.message)
    
    nfqueue.unbind()

def handle_outbound(pkt):
    tunneled_packet_bytes = pkt.get_payload()
    pkt.set_payload(tunnel_base_protocol.transform_outbound(tunneled_packet_bytes))
    pkt.accept()

def handle_inbound(pkt):
    packet_bytes = pkt.get_payload()
    pkt.set_payload(tunnel_base_protocol.transform_inbound(packet_bytes))
    pkt.accept()

def main():
    global tunnel_base_protocol
    tunnel_base_protocol = ICMPBase(True)

    inbound_thread = threading.Thread(target=inbound_nfqueue, args=(0, ))
    outbound_thread = threading.Thread(target=outbound_nfqueue, args=(0, ))

    inbound_thread.start()
    outbound_thread.start()

    inbound_thread.join()
    outbound_thread.join()
    
if __name__ == "__main__":
    main()