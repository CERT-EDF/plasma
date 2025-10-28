"""PCAP TLS Client Hello artifact dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from .helper import select_pcap_impl, stream_pcap_packets
from .helper.packet import pkt_base_record
from .helper.tls import (
    compute_ja3,
    get_servernames,
    has_tls_clt_hello,
    tls_clt_hello_layer,
)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for pkt in stream_pcap_packets(ctx.filepath):
        if not has_tls_clt_hello(pkt):
            continue
        layer = tls_clt_hello_layer(pkt)
        record = pkt_base_record(pkt)
        servernames = get_servernames(layer)
        ja3_string, ja3_hash = compute_ja3(layer)
        record.update(
            {
                'tls_ch_servernames': servernames,
                'tls_ch_ja3_hash': ja3_hash,
                'tls_ch_ja3_string': ja3_string,
            }
        )
        yield record


DISSECTOR = Dissector(
    slug='pcap_tls_client_hello',
    tags={Tag.PCAP},
    columns=[
        Column('pkt_time', DataType.STR),
        Column('pkt_src_ip', DataType.INET),
        Column('pkt_src_port', DataType.INT),
        Column('pkt_dst_ip', DataType.INET),
        Column('pkt_dst_port', DataType.INT),
        Column('tls_ch_servernames', DataType.STR),
        Column('tls_ch_ja3_hash', DataType.STR),
        Column('tls_ch_ja3_string', DataType.STR),
    ],
    description="TLS client hello from PCAP",
    select_impl=select_pcap_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
