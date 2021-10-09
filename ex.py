from netfilterqueue import NetfilterQueue
from scapy.all import *

# only useful with the following rules:
# -A INPUT -p icmp -j NFQUEUE --queue-num 1
# -A OUTPUT -p icmp -j NFQUEUE --queue-num 1

def print_and_accept(pkt):
    print("Received packet: {0}".format(pkt))
    packet_bytes = pkt.get_payload()
    scapy_packet = IP(packet_bytes)

    if str(scapy_packet[IP].src) == "10.0.0.1":
        print "OutboundPacket received!"
        scapy_packet[ICMP].payload = Raw("Toddypayload")
        scapy_packet[ICMP].chksum = None
        scapy_packet[IP].chksum = None
        scapy_packet[IP].len = None
        pkt.set_payload(raw(Ether(bytes(scapy_packet))))
    elif str(scapy_packet[IP].dst) == "10.0.0.1":
        print "InboundPacket received!"
        #scapy_packet.show()

    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()