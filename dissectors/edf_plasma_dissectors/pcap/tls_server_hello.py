"""PCAP TLS Server Hello artifact dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator
from scapy.layers.tls.all import TLSServerHello

from .helper import (
    compute_ja3s,
    pkt_base_record,
    select_pcap_impl,
    stream_pcap_packets,
)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for pkt in stream_pcap_packets(ctx.filepath):
        if TLSServerHello in pkt:
            tls_server_hello = pkt[TLSServerHello]
            record = pkt_base_record(pkt)
            ja3s_string, ja3s_hash = compute_ja3s(tls_server_hello)
            record.update(
                {
                    'tls_sh_ja3s_string': ja3s_string,
                    'tls_sh_ja3s_hash': ja3s_hash,
                }
            )
            yield record


DISSECTOR = Dissector(
    slug='pcap_tls_server_hello',
    tags={Tag.PCAP},
    columns=[
        Column('pkt_time', DataType.STR),
        Column('pkt_src_ip', DataType.INET),
        Column('pkt_src_port', DataType.INT),
        Column('pkt_dst_ip', DataType.INET),
        Column('pkt_dst_port', DataType.INT),
        Column('tls_sh_ja3s_string', DataType.STR),
        Column('tls_sh_ja3s_hash', DataType.STR),
    ],
    description="TLS server hello from PCAP",
    select_impl=select_pcap_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
