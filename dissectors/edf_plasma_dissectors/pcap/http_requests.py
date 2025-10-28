"""PCAP HTTP Requests artifact dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from .helper import select_pcap_impl, stream_pcap_packets
from .helper.decode import decode_utf8_string
from .helper.http import has_http_req, http_req_layer
from .helper.packet import pkt_base_record


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for pkt in stream_pcap_packets(ctx.filepath):
        if not has_http_req(pkt):
            continue
        layer = http_req_layer(pkt)
        record = pkt_base_record(pkt)
        if not record:
            continue
        content_length = decode_utf8_string(layer.Content_Length)
        if content_length:
            content_length = int(content_length)
        record.update(
            {
                'http_method': decode_utf8_string(layer.Method),
                'http_path': decode_utf8_string(layer.Path),
                'http_host': decode_utf8_string(layer.Host),
                'http_user_agent': decode_utf8_string(layer.User_Agent),
                'http_content_type': decode_utf8_string(layer.Content_Type),
                'http_content_length': content_length,
            }
        )
        yield record


DISSECTOR = Dissector(
    slug='pcap_http_requests',
    tags={Tag.PCAP},
    columns=[
        Column('pkt_time', DataType.STR),
        Column('pkt_src_ip', DataType.INET),
        Column('pkt_src_port', DataType.INT),
        Column('pkt_dst_ip', DataType.INET),
        Column('pkt_dst_port', DataType.INT),
        Column('http_method', DataType.STR),
        Column('http_path', DataType.STR),
        Column('http_host', DataType.STR),
        Column('http_user_agent', DataType.STR),
        Column('http_content_type', DataType.STR),
        Column('http_content_length', DataType.INT),
    ],
    description="HTTP requests from PCAP",
    select_impl=select_pcap_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
