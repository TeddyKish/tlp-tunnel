from netfilterqueue import NetfilterQueue
from scapy.all import *

def send_tcp(pkt):
    print("Received packet: {0}".format(pkt))
    packet_bytes = pkt.get_payload()
    #tcp_ether = Ether(packet_bytes)
    tcp_ip = IP(packet_bytes)
    
    icmp_packet = IP() / ICMP()
    icmp_packet[ICMP].type = 8 # echo request
    icmp_packet[ICMP].payload = Raw(packet_bytes)
    icmp_packet[ICMP].chksum = None
    icmp_packet[IP].chksum = None
    icmp_packet[IP].len = None

    # Copy values
    icmp_packet[IP].src = tcp_ip[IP].src
    icmp_packet[IP].dst = tcp_ip[IP].dst

    intermediary_packet = IP(bytes(icmp_packet))
    print intermediary_packet.summary()

    final_payload = raw(intermediary_packet)
    pkt.set_payload(final_payload)

    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(2, send_tcp)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()