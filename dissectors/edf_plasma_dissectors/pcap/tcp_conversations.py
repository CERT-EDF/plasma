"""PCAP TCP Conversations artifact dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from .helper import (
    IP,
    TCP,
    IPv6,
    Peer,
    PeerPair,
    TCPConversations,
    select_pcap_impl,
    stream_pcap_packets,
)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    tcp_convs = TCPConversations()
    for pkt in stream_pcap_packets(ctx.filepath):
        if TCP not in pkt:
            continue
        src_addr = pkt[IP].src if IP in pkt else pkt[IPv6].src
        dst_addr = pkt[IP].dst if IP in pkt else pkt[IPv6].dst
        peer_pair = PeerPair(
            src_peer=Peer(addr=src_addr, port=pkt[TCP].sport),
            dst_peer=Peer(addr=dst_addr, port=pkt[TCP].dport),
        )
        tcp_convs.append(peer_pair, pkt)
        # yield as processing progresses to prevent memory overflow
        while True:
            try:
                conv = tcp_convs.closed.pop()
            except IndexError:
                break
            yield conv.as_record()
    for conv in tcp_convs.conversations():
        yield conv.as_record()


DISSECTOR = Dissector(
    slug='pcap_tcp_conv',
    tags={Tag.PCAP},
    columns=[
        Column('src_ip', DataType.INET),
        Column('src_port', DataType.INT),
        Column('dst_ip', DataType.INET),
        Column('dst_port', DataType.INT),
        Column('beg_time', DataType.STR),
        Column('end_time', DataType.STR),
        Column('pkt_sent', DataType.INT),
        Column('pkt_recv', DataType.INT),
        Column('data_bytes_sent', DataType.INT),
        Column('data_bytes_recv', DataType.INT),
    ],
    description="TCP conversations from PCAP",
    select_impl=select_pcap_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
