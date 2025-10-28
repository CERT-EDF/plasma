"""HTTP helper"""

from edf_plasma_core.helper.importing import lazy_import

lazy_http = lazy_import('scapy.layers.http')


def has_http(pkt: 'scapy.all.Packet') -> bool:
    """Determine if pkt has a HTTPRequest layer"""
    return lazy_http.HTTP in pkt


def http_layer(pkt: 'scapy.all.Packet') -> 'scapy.layers.http.HTTP':
    """Extract HTTPRequest layer from packet"""
    return pkt[lazy_http.HTTP]


def has_http_req(pkt: 'scapy.all.Packet') -> bool:
    """Determine if pkt has a HTTPRequest layer"""
    return lazy_http.HTTPRequest in pkt


def http_req_layer(pkt: 'scapy.all.Packet') -> 'scapy.layers.http.HTTPRequest':
    """Extract HTTPRequest layer from packet"""
    return pkt[lazy_http.HTTPRequest]
