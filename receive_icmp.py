from netfilterqueue import NetfilterQueue
from scapy.all import *

PING_PAYLOAD_SUFFIX = "01234567"

def receive_icmp(pkt):
    print("Received packet: {0}".format(pkt))
    packet_bytes = pkt.get_payload()
    icmp_packet = IP(packet_bytes)
    
    if icmp_packet[ICMP].type == 0 and icmp_packet[Raw].load[-8:] != PING_PAYLOAD_SUFFIX:
        print "Received Tunneled ICMP Packet!"
        tcp_payload = icmp_packet[Raw].load
        pkt.set_payload(tcp_payload)

    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(3, receive_icmp)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()