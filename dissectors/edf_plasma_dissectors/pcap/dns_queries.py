"""PCAP DNS Queries artifact dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from .helper import select_pcap_impl, stream_pcap_packets
from .helper.decode import decode_utf8_string
from .helper.dns import dns_layer, dns_type, has_dns
from .helper.packet import is_raw, pkt_base_record

_LOGGER = get_logger('dissectors.pcap.dns_queries')


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    truncated = 0
    for pkt in stream_pcap_packets(ctx.filepath):
        if not has_dns(pkt):
            continue
        layer = dns_layer(pkt)
        if layer.qr or not layer.qdcount:
            continue
        record = pkt_base_record(pkt)
        if not record:
            continue
        for question in layer.qd:
            if is_raw(question):
                truncated += 1
                continue
            record.update(
                {
                    'dns_r_name': decode_utf8_string(question.qname),
                    'dns_r_type': dns_type(
                        question.qtype,
                        f'unknown type {question.qtype}',
                    ),
                }
            )
            yield record
    if truncated:
        ctx.register_error(f"skipped {truncated} truncated records")


DISSECTOR = Dissector(
    slug='pcap_dns_queries',
    tags={Tag.PCAP},
    columns=[
        Column('pkt_time', DataType.STR),
        Column('pkt_src_ip', DataType.INET),
        Column('pkt_src_port', DataType.INT),
        Column('pkt_dst_ip', DataType.INET),
        Column('pkt_dst_port', DataType.INT),
        Column('dns_r_name', DataType.STR),
        Column('dns_r_type', DataType.STR),
    ],
    description="DNS queries from PCAP",
    select_impl=select_pcap_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
