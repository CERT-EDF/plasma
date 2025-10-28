"""UDP helper"""

from edf_plasma_core.helper.importing import lazy_import

lazy_inet = lazy_import('scapy.layers.inet')

UDP_HEADER_SIZE = 8


def has_udp(pkt: 'scapy.all.Packet') -> bool:
    """Determine if pkt has a UDP layer"""
    return lazy_inet.UDP in pkt


def udp_layer(pkt: 'scapy.all.Packet') -> 'scapy.layers.inet.UDP':
    """Extract UDP layer from packet"""
    return pkt[lazy_inet.UDP]


def udp_data_len(pkt: 'scapy.all.Packet') -> int:
    """Compute UDP data length in bytes"""
    return pkt[lazy_inet.UDP].len - UDP_HEADER_SIZE
