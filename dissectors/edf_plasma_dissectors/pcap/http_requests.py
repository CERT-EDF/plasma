"""PCAP HTTP Requests artifact dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator
from scapy.layers.http import HTTPRequest

from .helper import (
    decode_utf8_string,
    pkt_base_record,
    select_pcap_impl,
    stream_pcap_packets,
)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for pkt in stream_pcap_packets(ctx.filepath):
        if HTTPRequest not in pkt:
            continue
        http_req = pkt[HTTPRequest]
        record = pkt_base_record(pkt)
        if not record:
            continue
        content_length = decode_utf8_string(http_req.Content_Length)
        if content_length:
            content_length = int(content_length)
        record.update(
            {
                'http_method': decode_utf8_string(http_req.Method),
                'http_path': decode_utf8_string(http_req.Path),
                'http_host': decode_utf8_string(http_req.Host),
                'http_user_agent': decode_utf8_string(http_req.User_Agent),
                'http_content_type': decode_utf8_string(http_req.Content_Type),
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
    description="DNS http requests from PCAP",
    select_impl=select_pcap_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
