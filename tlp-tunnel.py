"""
Transport-Layer-Protocol tunnel:
This project enables tunneling of transport layer protocols within Tunnel Base Protocols (for example, TCP over ICMP).
Currently, available TBPs are either ICMP/DNS (adding additional TBPs is very simple).
"""

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
    This is an abstract base class for every TBP.
    It represents the base protocol, over which the tunneling occurs (i.e. ICMP, DNS etc..).
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def transform_outbound(self, packet_bytes):
        """
        Transforms the outbound packet to a TBP packet.
        """
        pass

    @abstractmethod
    def transform_inbound(self, packet_bytes):
        """
        Transforms the inbound TBP packet to the tunneled packet when the inbound packet contains a tunneled payload.
        When the inbound TBP packet doesn't contain a payload (normal transmission of TBP packets), the packet remains the same.
        """
        pass

class ICMPBase(TunnelBaseProtocol):
    """
    Represents ICMP as the base protocol.
    """
    def __init__(self, is_requester):
        """
        The requester information is important to distinguish the current machine's role.
        The isolated machine sends echo requests and receives echo replies, and the proxy machine does the opposite.
        """
        if is_requester:
            self.outbound_icmp_message_type = ICMP_ECHO_REQUEST_ID
            self.inbound_icmp_message_type  = ICMP_ECHO_REPLY_ID
        else:
            self.outbound_icmp_message_type = ICMP_ECHO_REPLY_ID
            self.inbound_icmp_message_type  = ICMP_ECHO_REQUEST_ID

    def transform_outbound(self, packet_bytes):
        """
        Transforms the outbound packet to an ICMP packet.
        """
        tunneled_packet = IP(packet_bytes)

        # Packet initialization
        icmp_packet = IP() / ICMP()
        icmp_packet[ICMP].type = self.outbound_icmp_message_type
        icmp_packet[ICMP].payload = Raw(packet_bytes) 
        icmp_packet[ICMP].chksum = None
        icmp_packet[IP].chksum = None
        icmp_packet[IP].len = None

        # Use original addressing values
        icmp_packet[IP].src = tunneled_packet[IP].src
        icmp_packet[IP].dst = tunneled_packet[IP].dst

        intermediary_packet = IP(bytes(icmp_packet))
        return raw(intermediary_packet)

    def transform_inbound(self, packet_bytes):
        """
        Transforms the inbound ICMP packet(if it contains a tunneled payload) to the tunneled packet.
        """
        icmp_packet = IP(packet_bytes)
    
        # Checks whether the inbound ICMP packet contains a tunneled payload
        if icmp_packet[ICMP].type == self.inbound_icmp_message_type and icmp_packet[Raw].load[-8:] != ICMP_PING_PAYLOAD_SUFFIX:
            return icmp_packet[Raw].load

        return packet_bytes

class DNSBase(TunnelBaseProtocol):
    """
    Represents DNS as the base protocol.
    """
    def __init__(self, is_requester):
        #TODO: add correct functionality for DNS sender-receiver relationship
        if is_requester:
            pass
        else:
            pass

    def transform_outbound(self, packet_bytes):
        """
        Transforms the outbound packet to a DNS packet.
        """
        tunneled_packet = IP(packet_bytes)

        # Packet initialization
        dns_packet = IP() / DNS()
        #TODO: add dns internal stuff here

        dns_packet[IP].chksum = None
        dns_packet[IP].len = None

        # Use original addressing values
        dns_packet[IP].src = tunneled_packet[IP].src
        dns_packet[IP].dst = tunneled_packet[IP].dst

        intermediary_packet = IP(bytes(dns_packet))
        return raw(intermediary_packet)

    def transform_inbound(self, packet_bytes):
        """
        Transforms the inbound DNS packet to the tunneled packet when it contains a tunneled payload, otherwise nothing.
        """
        dns_packet = IP(packet_bytes)
    
        # TODO: Check here if the DNS packet contains a tunneled payload or not, and return the tunneled/original payload accordingly
        return packet_bytes

# Functions
def nfqueue(queue_num, is_inbound):
    """
    Creates the nfqueue object and binds <queue_num> to the inbound/outbound handling functions.
    """
    nfqueue = NetfilterQueue()

    if is_inbound:
        nfqueue.bind(queue_num, handle_inbound)
    else:
        nfqueue.bind(queue_num, handle_outbound)

    try:
        nfqueue.run()    
    except Exception as e:
        print(e.message)
    
    nfqueue.unbind()

def handle_outbound(pkt):
    """
    Handles outbound packets by tunneling the payload inside the TBP packet.
    """
    packet_bytes = pkt.get_payload()
    pkt.set_payload(tunnel_base_protocol.transform_outbound(packet_bytes))
    pkt.accept()

def handle_inbound(pkt):
    """
    Handles inbound packets using the TBP's inbound packet handler.
    """
    packet_bytes = pkt.get_payload()
    pkt.set_payload(tunnel_base_protocol.transform_inbound(packet_bytes))
    pkt.accept()

def get_tbp_instance(base_protocol):
    """
    Returns a TBP class according to <base_protocol>.
    """
    tbp_class_dict = {}
    tbp_class_dict["icmp"] = ICMPBase
    tbp_class_dict["dns"]  = DNSBase
    
    return tbp_class_dict[base_protocol]

def main():
    """
    Parses the user's arguments and uses them to call the nfqueue functions.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("protocol", help="Defines the base protocol over which the tunneling will be performed", type=str, choices=["icmp", "dns"])
    parser.add_argument("-i", "--in_queue", help="Specifies the queue number for inbound tunnel-base-protocol packets", type=int, default=DEF_INBOUND_QUEUENUM)
    parser.add_argument("-o", "--out_queue", help="Specifies the queue number for outbound tunnel-base-protocol packets", type=int, default=DEF_OUTBOUND_QUEUENUM)
    parser.add_argument("--isolated", help="Specifies whether the current machine is the network-restricted machine", action="store_true")
    args = parser.parse_args()

    # Defines the TBP for this instance of the tlp-tunnel
    global tunnel_base_protocol
    tunnel_base_protocol = get_tbp_instance(args.protocol)(args.isolated)

    inbound_thread = threading.Thread(target=nfqueue, args=(args.in_queue, args.isolated))
    outbound_thread = threading.Thread(target=nfqueue, args=(args.out_queue, not args.isolated))

    inbound_thread.start()
    outbound_thread.start()

    inbound_thread.join()
    outbound_thread.join()
    
if __name__ == "__main__":
    main()