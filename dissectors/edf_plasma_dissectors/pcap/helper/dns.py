"""DNS helper"""

from typing import Any

from edf_plasma_core.helper.importing import lazy_import

lazy_dns = lazy_import('scapy.layers.dns')


def has_dns(pkt: 'scapy.all.Packet') -> bool:
    """Determine if pkt has a DNS layer"""
    return lazy_dns.DNS in pkt


def dns_layer(pkt: 'scapy.all.Packet') -> 'scapy.layers.dns.DNS':
    """Extract DNS layer from packet"""
    return pkt[lazy_dns.DNS]


def dns_type(value: int, default: Any = None) -> str:
    """Retrieve string representation of dns type"""
    return lazy_dns.dnstypes.get(value, default)
