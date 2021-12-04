from scapy.all import ICMP, IP, Raw
from utils import *

class IcmpResult:
    def __init__(self, validation_res, pkt=None, err=''):
        self.pkt = pkt
        self.validation_res = validation_res
        self.err = err


class TlpDetector:
    """ This class validates ICMP packets and attempts to block ICMP tunneling. 
        Usage - call the 'validate_packet' function and pass the packet to validate as a parameter.
                Return value is an 'IcmpResult' object, which holds three members:
                * validation_res(bool) - whether the packet passed validation or not
                * pkt(ICMP) - a fixed ICMP packet.
                              If 'res' is True or the packet couldn't be fixed, 'pkt' will be None
                * err(str) - if 'res' is False, this will hold the explanation to why the validation failed """
    
    def validate_packet(self, packet):
        """ The validation entry point """
        return self.sort_by_type(packet)

    def sort_by_type(self, packet):
        """ Sorts ICMP packets by their 'type' field.
            Each type has its own validation function that handles it."""
            
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
        
        error = err_index_to_desc(IcmpError.INVALID_TYPE)
        return IcmpResult(IcmpRes.DROP, err=error)

    def validate_echo(self, pkt):
        """ Validates ICMP messages of type ECHO REQUEST/ECHO REPLY """

        fixed_pkt = duplicate_packet(pkt)
        res = IcmpRes.OK
        error = ''

        if (IcmpCode.ECHO_CODE != pkt.code):
            error = err_index_to_desc(IcmpError.INVALID_CODE)
            return IcmpResult(IcmpRes.DROP, err=error)

        if (b'' != pkt.unused):
            fixed_pkt.unused = ''
            error = err_index_to_desc(IcmpError.INVALID_DATA)
            res = IcmpRes.FIX

        if Raw in pkt:
            if (b'' != pkt.payload and
                DEFAULT_ECHO_PAYLOAD != pkt.payload):
                fixed_pkt.load = DEFAULT_ECHO_PAYLOAD
                error = err_index_to_desc(IcmpError.INVALID_DATA)
                res = IcmpRes.FIX

        fixed_pkt.chksum = get_checksum(fixed_pkt)
        return IcmpResult(res, fixed_pkt, error)

    def validate_dest_unreachable(self, pkt):
        """ Validates ICMP messages of type DESTINATION UNREACHABLE """

        fixed_pkt = duplicate_packet(pkt)/IP()
        error = ''
        res = IcmpRes.OK

        if (IcmpCode.DEST_UNREACHABLE_MAX < pkt.code or
            IcmpCode.DEST_UNREACHABLE_MIN > pkt.code):
            error = err_index_to_desc(IcmpError.INVALID_CODE)
            return IcmpResult(IcmpRes.DROP, err=error)

        if (b'' != pkt.unused):
            fixed_pkt.unused = ''
            error = err_index_to_desc(IcmpError.INVALID_DATA)
            res = IcmpRes.FIX

        if (IP_VERSION != pkt[IP].version):    
            fixed_pkt[IP].version = IP_VERSION
            error = err_index_to_desc(IcmpError.INVALID_IP_VERSION)
            res = IcmpRes.FIX

        if (MAX_TTL < pkt[IP].ttl):
            fixed_pkt[IP].ttl = MAX_TTL
            error = err_index_to_desc(IcmpError.INVALID_TTL)
            res = IcmpRes.FIX

        if (ICMP_PROTO != pkt[IP].proto):
            fixed_pkt[IP].proto = ICMP_PROTO
            error = err_index_to_desc(IcmpError.INVALID_PROTOCOL)
            res =  IcmpRes.FIX

        if Raw in pkt:
            fixed_pkt.load = ''
            error = err_index_to_desc(IcmpError.INVALID_DATA)
            res = IcmpRes.FIX

        fixed_pkt.chksum = get_checksum(fixed_pkt)
        return IcmpResult(res, fixed_pkt, error)

    def validate_redirect(self, pkt):
        """ Validates ICMP messages of type REDIRECT """

        fixed_pkt = duplicate_packet(pkt)/IP()
        error = ''
        res = IcmpRes.OK

        if (IcmpCode.REDIRECT_MAX < pkt.code or
            IcmpCode.REDIRECT_MIN > pkt.code):
            error = err_index_to_desc(IcmpError.INVALID_CODE)
            return IcmpResult(IcmpRes.DROP, err=error)

        if (IP_VERSION != pkt[IP].version):    
            fixed_pkt[IP].version = IP_VERSION
            error = err_index_to_desc(IcmpError.INVALID_IP_VERSION)
            res = IcmpRes.FIX

        if (MAX_TTL < pkt[IP].ttl):
            fixed_pkt[IP].ttl = MAX_TTL
            error = err_index_to_desc(IcmpError.INVALID_TTL)
            res = IcmpRes.FIX

        if (ICMP_PROTO != pkt[IP].proto):
            fixed_pkt[IP].proto = ICMP_PROTO
            error = err_index_to_desc(IcmpError.INVALID_PROTOCOL)
            res =  IcmpRes.FIX

        if Raw in pkt:  
            fixed_pkt.load = ''
            error = err_index_to_desc(IcmpError.INVALID_DATA)
            res = IcmpRes.FIX

        fixed_pkt.chksum = get_checksum(fixed_pkt)
        return IcmpResult(res, fixed_pkt, error)

    def validate_time_exceeded(self, pkt):
        """ Validates ICMP messages of type TIME EXCEEDED """

        fixed_pkt = duplicate_packet(pkt)/IP()
        error = ''
        res = IcmpRes.OK

        if (IcmpCode.TIME_EXCEEDED_MAX != pkt.code and
            IcmpCode.TIME_EXCEEDED_MIN != pkt.code):
            error = err_index_to_desc(IcmpError.INVALID_CODE)
            return IcmpResult(IcmpRes.DROP, error)

        if (b'' != pkt.unused):
            fixed_pkt.unused = ''
            error = err_index_to_desc(IcmpError.INVALID_DATA)
            res = IcmpRes.FIX

        if (IP_VERSION != pkt[IP].version):    
            fixed_pkt[IP].version = IP_VERSION
            error = err_index_to_desc(IcmpError.INVALID_IP_VERSION)
            res = IcmpRes.FIX

        if (MAX_TTL < pkt[IP].ttl):
            fixed_pkt[IP].ttl = MAX_TTL
            error = err_index_to_desc(IcmpError.INVALID_TTL)
            res = IcmpRes.FIX

        if (ICMP_PROTO != pkt[IP].proto):
            fixed_pkt[IP].proto = ICMP_PROTO
            error = err_index_to_desc(IcmpError.INVALID_PROTOCOL)
            res =  IcmpRes.FIX

        if Raw in pkt:
            fixed_pkt.load = ''
            error = err_index_to_desc(IcmpError.INVALID_DATA)
            res = IcmpRes.FIX

        fixed_pkt.chksum = get_checksum(fixed_pkt)
        return (res, fixed_pkt, error)

def duplicate_packet(pkt):
    """ Duplicates a given ICMP packet - that will be used as the fixed packet """
    return ICMP(type=pkt.type, code=pkt.code)

    