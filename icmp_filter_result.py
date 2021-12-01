from scapy.all import ICMP

class IcmpResult:
    def __init__(self, validation_res, pkt=None, err=''):
        self.pkt = pkt
        self.validation_res = validation_res
        self.err = err