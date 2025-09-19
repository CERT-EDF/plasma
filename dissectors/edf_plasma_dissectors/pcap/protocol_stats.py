"""PCAP Protocol Statistics artifact dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.inet import ICMP

from .helper import (
    TCP,
    UDP,
    UnidirectionalCounter,
    select_pcap_impl,
    stream_pcap_packets,
    tcp_data_len,
    udp_data_len,
)


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
        if TCP in pkt:
            counter = 'tcp'
            data_bytes_cnt = tcp_data_len(pkt)
        if UDP in pkt:
            counter = 'udp'
            data_bytes_cnt = udp_data_len(pkt)
        if UDP in pkt and DNS in pkt:
            counter = 'dns'
            data_bytes_cnt = len(pkt[DNS])
        if HTTP in pkt:
            counter = 'http'
            data_bytes_cnt = len(pkt[HTTP])
        if ICMP in pkt:
            counter = 'icmp'
            data_bytes_cnt = len(pkt[ICMP])
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
