# Libraries
import argparse
import threading
from netfilterqueue import NetfilterQueue
from scapy.all import *

# Constants
DEF_OUTBOUND_QUEUENUM = 2
DEF_INBOUND_QUEUENUM  =  3

ICMP_PING_PAYLOAD_SUFFIX = "01234567"
ICMP_ECHO_REQUEST_ID = 0
ICMP_ECHO_REPLY_ID   = 8

def handle_inbound(queue_num):
    print("Started listening for inbound packets...")
    inbound_queue = NetfilterQueue()
    inbound_queue.bind(DEF_INBOUND_QUEUENUM, transform_inbound)
    try:
        inbound_queue.run()    
    except Exception as e:
        print(e.message)
    
    inbound_queue.unbind()

def handle_outbound(queue_num):
    print("Started listening for outbound packets...")
    outbound_queue = NetfilterQueue()
    outbound_queue.bind(DEF_OUTBOUND_QUEUENUM, transform_outbound)

    try:
        outbound_queue.run()
    except Exception as e:
        print(e.message)

    outbound_queue.unbind()

def transform_inbound(pkt):
    print("Received packet: {0}".format(pkt))
    packet_bytes = pkt.get_payload()
    icmp_packet = IP(packet_bytes)
    
    if icmp_packet[ICMP].type == ICMP_ECHO_REQUEST_ID and icmp_packet[Raw].load[-8:] != ICMP_PING_PAYLOAD_SUFFIX:
        print "Received Tunneled ICMP Packet!"
        tcp_payload = icmp_packet[Raw].load
        pkt.set_payload(tcp_payload)

    pkt.accept()

def transform_outbound(pkt):
    print("Received packet: {0}".format(pkt))
    packet_bytes = pkt.get_payload()
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

def main():
    inbound_thread = threading.Thread(target=handle_inbound, args=(0, ))
    outbound_thread = threading.Thread(target=handle_outbound, args=(0, ))

    inbound_thread.start()
    outbound_thread.start()

    inbound_thread.join()
    outbound_thread.join()
    
if __name__ == "__main__":
    main()