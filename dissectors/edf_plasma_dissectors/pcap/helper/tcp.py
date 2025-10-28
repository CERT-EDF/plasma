"""TCP helper"""

from edf_plasma_core.helper.importing import lazy_import

lazy_inet = lazy_import('scapy.layers.inet')


def has_tcp(pkt: 'scapy.all.Packet') -> bool:
    """Determine if pkt has a TCP layer"""
    return lazy_inet.TCP in pkt


def tcp_layer(pkt: 'scapy.all.Packet') -> 'scapy.layers.inet.TCP':
    """Extract TCP layer from packet"""
    return pkt[lazy_inet.TCP]


def tcp_data_len(pkt: 'scapy.all.Packet') -> int:
    """Compute TCP data length in bytes"""
    return len(pkt[lazy_inet.TCP]) - (pkt[lazy_inet.TCP].dataofs * 4)
