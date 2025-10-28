"""ICMP helper"""

from edf_plasma_core.helper.importing import lazy_import

lazy_inet = lazy_import('scapy.layers.inet')


def has_icmp(pkt: 'scapy.all.Packet') -> bool:
    """Determine if pkt has a TCP layer"""
    return lazy_inet.ICMP in pkt


def icmp_layer(pkt: 'scapy.all.Packet') -> 'scapy.layers.inet.ICMP':
    """Extract ICMP layer from packet"""
    return pkt[lazy_inet.ICMP]
