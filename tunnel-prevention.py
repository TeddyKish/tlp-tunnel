from netfilterqueue import NetfilterQueue
from scapy.all import *
from tlp_detector import * 

# only useful with the following rules:
# -A FORWARD/INPUT/OUTPUT -p <protocol> -j NFQUEUE --queue-num 1

def print_and_accept(pkt):
    detector = TlpDetector()

    packet_bytes = pkt.get_payload()
    scapy_packet_form = IP(packet_bytes)
    info = detector.validate_packet(scapy_packet_form)    

    if info.validation_res == IcmpRes.OK:
        pkt.accept()
    elif info.validation_res == IcmpRes.FIX:
        print "Received incorrect ICMP packet, fixed"
        info.pkt[IP].len = None
        info.pkt[IP].chksum = None
        info.pkt[ICMP].chksum = None

        fixed_packet = IP(bytes(info.pkt))
        pkt.set_payload(raw(fixed_packet))
        pkt.accept()
    elif info.validation_res == IcmpRes.DROP:
        print "Received potentially malicious ICMP packet, dropped"
        print info.err
        pkt.drop()

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)

try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()
