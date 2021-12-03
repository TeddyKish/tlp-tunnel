from scapy.all import ICMP

class IcmpRes():
    OK = 0
    FIX = 1
    DROP = 2

class IcmpError():
    INVALID_TYPE = 0
    INVALID_CODE = 1
    INVALID_DATA = 2
    INVALID_IP_VERSION = 3
    INVALID_PROTOCOL = 4
    INVALID_TTL = 5

class IcmpType():
    ECHO_REPLY = 0
    DEST_UNREACHABLE = 3
    REDIRECT = 5
    ECHO_REQUEST = 8
    TIME_EXCEEDED = 11

class IcmpCode():
    ECHO_CODE = 0
    DEST_UNREACHABLE_MIN = 0
    DEST_UNREACHABLE_MAX = 15
    REDIRECT_MIN = 0
    REDIRECT_MAX = 3
    TIME_EXCEEDED_MIN = 0
    TIME_EXCEEDED_MAX = 1


ICMP_PROTO = 1
MAX_TTL = 255
IP_VERSION = 4


def get_checksum(msg):
    del msg.chksum
    msg.show2()
    return msg.chksum

def err_index_to_desc(index):
    if (IcmpError.INVALID_TYPE == index):
        return "Invalid ICMP type"
    elif (IcmpError.INVALID_CODE == index):
        return "Invalid ICMP code"
    elif (IcmpError.INVALID_DATA == index):
        return "Invalid data field"
    elif (IcmpError.INVALID_IP_VERSION == index):
        return "Invalid IP version"
    elif (IcmpError.INVALID_PROTOCOL == index):
        return "Invalid protocol - should be ICMP"
    elif (IcmpError.INVALID_TTL == index):
        return "Invalid ttl - larger than max allowed"