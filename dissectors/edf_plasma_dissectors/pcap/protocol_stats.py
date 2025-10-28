"""PCAP Protocol Statistics artifact dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from .helper import select_pcap_impl, stream_pcap_packets
from .helper.conv import UnidirectionalCounter
from .helper.dns import dns_layer, has_dns
from .helper.http import has_http, http_layer
from .helper.icmp import has_icmp, icmp_layer
from .helper.tcp import has_tcp, tcp_data_len
from .helper.udp import has_udp, udp_data_len


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    counters = {
        'tcp': UnidirectionalCounter(),
        'udp': UnidirectionalCounter(),
        'dns': UnidirectionalCounter(),
        'http': UnidirectionalCounter(),
        'icmp': UnidirectionalCounter(),
    }
    for pkt in stream_pcap_packets(ctx.filepath):
        counter = None
        data_bytes_cnt = 0
        if has_tcp(pkt):
            counter = 'tcp'
            data_bytes_cnt = tcp_data_len(pkt)
        if has_udp(pkt):
            counter = 'udp'
            data_bytes_cnt = udp_data_len(pkt)
        if has_dns(pkt):
            counter = 'dns'
            data_bytes_cnt = len(dns_layer(pkt))
        if has_http(pkt):
            counter = 'http'
            data_bytes_cnt = len(http_layer(pkt))
        if has_icmp(pkt):
            counter = 'icmp'
            data_bytes_cnt = len(icmp_layer(pkt))
        if counter:
            counters[counter].add(data_bytes_cnt)
    for protocol, counter in counters.items():
        yield {
            'pkt_proto': protocol,
            'pkt_count': counter.pkt_cnt,
            'pkt_bytes': counter.data_bytes_cnt,
        }


DISSECTOR = Dissector(
    slug='pcap_proto_stats',
    tags={Tag.PCAP},
    columns=[
        Column('pkt_proto', DataType.STR),
        Column('pkt_count', DataType.INT),
        Column('pkt_bytes', DataType.INT),
    ],
    description="protocols from PCAP",
    select_impl=select_pcap_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
