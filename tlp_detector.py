from icmp_filter_result import IcmpResult
from scapy.all import ICMP, IP
from utils import *

class TlpDetector:
    """ This class validates ICMP packets and attempts to block ICMP tunneling 
        Usage - call the 'validate_packet' function and pass the packet to validate as a parameter
                return value is an 'IcmpResult' object, which holds three members:
                * res(bool) - whether the packet passed validation or not
                * pkt(ICMP) - a fixed ICMP packet.
                              If 'res' is True or the packet couldn't be fixed, 'pkt' will be None
                * error(str) - if 'res' is False, this will hold the explanation to why the validation failed """
    
    def validate_packet(self, packet:ICMP) -> bool:
        return self.sort_by_type(packet)

    def sort_by_type(self, packet) -> bool:
        if (IcmpType.ECHO_REPLY == packet.type):
            return self.validate_echo(packet)
        elif (IcmpType.DEST_UNREACHABLE == packet.type):
            return self.validate_dest_unreachable(packet)
        elif (IcmpType.REDIRECT == packet.type):
            return self.validate_redirect(packet)
        elif (IcmpType.ECHO_REQUEST == packet.type):
            return self.validate_echo(packet)
        elif (IcmpType.TIME_EXCEEDED == packet.type):
            return self.validate_time_exceeded(packet)
        
        error = err_index_to_desc(err.INVALID_TYPE)
        return IcmpResult(False, err=error)

    def validate_echo(self, pkt:ICMP) -> bool:
        fixed_pkt = duplicate_packet(pkt)
        res = True
        error = ''

        if (IcmpCode.ECHO_CODE != pkt.code):
            error = err_index_to_desc(err.INVALID_CODE)
            return IcmpResult(False, err=error)

        if (b'' != pkt.unused):
            fixed_pkt.unused = ''
            error = err_index_to_desc(err.INVALID_DATA)
            res = False

        fixed_pkt.chksum = get_checksum(fixed_pkt)
        return IcmpResult(res, fixed_pkt, error)

    def validate_dest_unreachable(self, pkt) -> bool:
        fixed_pkt = duplicate_packet(pkt)/IP()
        error = ''
        res = True

        if (IcmpCode.DEST_UNREACHABLE_MAX < pkt.code or
            IcmpCode.DEST_UNREACHABLE_MIN > pkt.code):
            error = err_index_to_desc(err.INVALID_CODE)
            return IcmpResult(False, err=error)

        if (b'' != pkt.unused):
            fixed_pkt.unused = ''
            error = err_index_to_desc(err.INVALID_DATA)
            res = False

        if (IP_VERSION != pkt[IP].version):    
            fixed_pkt[IP].version = IP_VERSION
            error = err_index_to_desc(err.INVALID_IP_VERSION)
            res = False

        if (MAX_TTL < pkt[IP].ttl):
            fixed_pkt[IP].ttl = MAX_TTL
            error = err_index_to_desc(err.INVALID_TTL)
            res = False

        if (ICMP_PROTO != pkt[IP].proto):
            fixed_pkt[IP].proto = ICMP_PROTO
            error = err_index_to_desc(err.INVALID_PROTOCOL)
            res =  False

        fixed_pkt.chksum = get_checksum(fixed_pkt)
        return IcmpResult(res, fixed_pkt, error)

    def validate_redirect(self, pkt) -> bool:
        fixed_pkt = duplicate_packet(pkt)/IP()
        error = ''
        res = True

        if (IcmpCode.REDIRECT_MAX < pkt.code or
            IcmpCode.REDIRECT_MIN > pkt.code):
            error = err_index_to_desc(err.INVALID_CODE)
            return IcmpResult(False, err=error)

        if (IP_VERSION != pkt[IP].version):    
            fixed_pkt[IP].version = IP_VERSION
            error = err_index_to_desc(err.INVALID_IP_VERSION)
            res = False

        if (MAX_TTL < pkt[IP].ttl):
            fixed_pkt[IP].ttl = MAX_TTL
            error = err_index_to_desc(err.INVALID_TTL)
            res = False

        if (ICMP_PROTO != pkt[IP].proto):
            fixed_pkt[IP].proto = ICMP_PROTO
            error = err_index_to_desc(err.INVALID_PROTOCOL)
            res =  False

        fixed_pkt.chksum = get_checksum(fixed_pkt)
        return IcmpResult(res, fixed_pkt, error)

    def validate_time_exceeded(self, pkt) -> bool:
        fixed_pkt = duplicate_packet(pkt)/IP()
        error = ''
        res = True

        if (IcmpCode.TIME_EXCEEDED_MAX != pkt.code and
            IcmpCode.TIME_EXCEEDED_MIN != pkt.code):
            error = err_index_to_desc(err.INVALID_CODE)
            return IcmpResult(False, error)

        if (b'' != pkt.unused):
            fixed_pkt.unused = ''
            error = err_index_to_desc(err.INVALID_DATA)
            res = False

        if (IP_VERSION != pkt[IP].version):    
            fixed_pkt[IP].version = IP_VERSION
            error = err_index_to_desc(err.INVALID_IP_VERSION)
            res = False

        if (MAX_TTL < pkt[IP].ttl):
            fixed_pkt[IP].ttl = MAX_TTL
            error = err_index_to_desc(err.INVALID_TTL)
            res = False

        if (ICMP_PROTO != pkt[IP].proto):
            fixed_pkt[IP].proto = ICMP_PROTO
            error = err_index_to_desc(err.INVALID_PROTOCOL)
            res =  False

        fixed_pkt.chksum = get_checksum(fixed_pkt)
        return (res, fixed_pkt, error)

def duplicate_packet(pkt:ICMP) -> ICMP:
    return ICMP(type=pkt.type, code=pkt.code)

    