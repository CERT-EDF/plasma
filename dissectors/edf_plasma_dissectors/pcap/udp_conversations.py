"""PCAP UDP Converations artifact dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from .helper import select_pcap_impl, stream_pcap_packets
from .helper.conv import Peer, PeerPair
from .helper.ipv4 import has_ipv4, ipv4_layer
from .helper.ipv6 import ipv6_layer
from .helper.udp import has_udp, udp_layer
from .helper.udp_conv import UDPConversations


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    udp_convs = UDPConversations()
    for pkt in stream_pcap_packets(ctx.filepath):
        if not has_udp(pkt):
            continue
        tp_layer = udp_layer(pkt)
        ip_layer = ipv4_layer(pkt) if has_ipv4(pkt) else ipv6_layer(pkt)
        peer_pair = PeerPair(
            src_peer=Peer(addr=ip_layer.src, port=tp_layer.sport),
            dst_peer=Peer(addr=ip_layer.dst, port=tp_layer.dport),
        )
        udp_convs.append(peer_pair, pkt)
    for conv in udp_convs.conversations():
        yield conv.as_record()


DISSECTOR = Dissector(
    slug='pcap_udp_conv',
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
    description="UDP conversations from PCAP",
    select_impl=select_pcap_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
