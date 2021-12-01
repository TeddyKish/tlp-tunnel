from enum import IntEnum
from scapy.all import ICMP

err = IntEnum('Error', [
    'INVALID_TYPE',
    'INVALID_CODE',
    'INVALID_DATA',
    'INVALID_IP_VERSION',
    'INVALID_PROTOCOL',
    'INVALID_TTL',
])

class IcmpType(IntEnum):
    ECHO_REPLY = 0
    DEST_UNREACHABLE = 3
    REDIRECT = 5
    ECHO_REQUEST = 8
    TIME_EXCEEDED = 11

class IcmpCode(IntEnum):
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


def get_checksum(msg: ICMP) -> int:
    del msg.chksum
    msg.show2()
    return msg.chksum

def err_index_to_desc(index):
    if (err.INVALID_TYPE == index):
        return "Invalid ICMP type"
    elif (err.INVALID_CODE == index):
        return "Invalid ICMP code"
    elif (err.INVALID_DATA == index):
        return "Invalid data field"
    elif (err.INVALID_IP_VERSION == index):
        return "Invalid IP version"
    elif (err.INVALID_PROTOCOL == index):
        return "Invalid protocol - should be ICMP"
    elif (err.INVALID_TTL == index):
        return "Invalid ttl - larger than max allowed"