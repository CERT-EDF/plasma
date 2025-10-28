"""IPv4 helper"""

from edf_plasma_core.helper.importing import lazy_import

lazy_inet = lazy_import('scapy.layers.inet')


def has_ipv4(pkt: 'scapy.all.Packet') -> bool:
    """Determine if pkt has a IPv4 layer"""
    return lazy_inet.IP in pkt


def ipv4_layer(pkt: 'scapy.all.Packet') -> 'scapy.layers.inet.IP':
    """Extract IPv4 layer from packet"""
    return pkt[lazy_inet.IP]
