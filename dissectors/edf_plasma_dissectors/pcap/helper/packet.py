"""Packet helper"""

from edf_plasma_core.helper.datetime import (
    datetime,
    timedelta,
    timezone,
    to_iso_fmt,
)
from edf_plasma_core.helper.importing import lazy_import

from .ipv4 import has_ipv4, ipv4_layer
from .ipv6 import has_ipv6, ipv6_layer
from .tcp import has_tcp, tcp_layer
from .udp import has_udp, udp_layer

lazy_packet = lazy_import('scapy.packet')


def is_raw(pkt: 'scapy.all.Packet') -> bool:
    """Determine if packet is Raw"""
    return isinstance(pkt, lazy_packet.Raw)


def raw_layer(pkt: 'scapy.all.Packet') -> 'scapy.packet.Raw':
    """Retrieve Raw layer"""
    return pkt[lazy_packet.Raw]


def pkt_time(pkt: 'scapy.all.Packet') -> datetime:
    """Extract time from packet"""
    dtv = datetime.fromtimestamp(int(pkt.time), tz=timezone.utc)
    microseconds = int(pkt.time * 1000000) % 1000000
    dtv += timedelta(microseconds=microseconds)
    return dtv


def pkt_base_record(pkt: 'scapy.all.Packet'):
    """Generic record for a packet"""
    net_header = None
    if has_ipv4(pkt):
        net_header = ipv4_layer(pkt)
    if has_ipv6(pkt):
        net_header = ipv6_layer(pkt)
    if not net_header:
        return None
    tpt_header = None
    if has_tcp(pkt):
        tpt_header = tcp_layer(pkt)
    if has_udp(pkt):
        tpt_header = udp_layer(pkt)
    if not tpt_header:
        return None
    return {
        'pkt_time': to_iso_fmt(pkt_time(pkt)),
        'pkt_src_ip': net_header.src,
        'pkt_src_port': tpt_header.sport,
        'pkt_dst_ip': net_header.dst,
        'pkt_dst_port': tpt_header.dport,
    }
