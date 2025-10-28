"""IPv6 helper"""

from edf_plasma_core.helper.importing import lazy_import

lazy_inet6 = lazy_import('scapy.layers.inet6')


def has_ipv6(pkt: 'scapy.all.Packet') -> bool:
    """Determine if pkt has a IPv6 layer"""
    return lazy_inet6.IPv6 in pkt


def ipv6_layer(pkt: 'scapy.all.Packet') -> 'scapy.layers.inet6.IPv6':
    """Extract IPv6 layer from packet"""
    return pkt[lazy_inet6.IPv6]
