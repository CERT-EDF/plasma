"""PCAP TLS Certificate artifact dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator
from scapy.layers.tls.all import TLSCertificate

from .helper import pkt_base_record, select_pcap_impl, stream_pcap_packets


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for pkt in stream_pcap_packets(ctx.filepath):
        if TLSCertificate in pkt:
            record = pkt_base_record(pkt)
            tls_certificate = pkt[TLSCertificate]
            for _, certificate in tls_certificate.certs:
                record.update(
                    {
                        'crt_issuer': certificate.issuer_str,
                        'crt_subject': certificate.subject_str,
                        'crt_not_before': certificate.notBefore_str,
                        'crt_not_after': certificate.notAfter_str,
                    }
                )
                yield record


DISSECTOR = Dissector(
    slug='pcap_tls_cert',
    tags={Tag.PCAP},
    columns=[
        Column('pkt_time', DataType.STR),
        Column('pkt_src_ip', DataType.INET),
        Column('pkt_src_port', DataType.INT),
        Column('pkt_dst_ip', DataType.INET),
        Column('pkt_dst_port', DataType.INT),
        Column('crt_issuer', DataType.STR),
        Column('crt_subject', DataType.STR),
        Column('crt_not_before', DataType.STR),
        Column('crt_not_after', DataType.STR),
    ],
    description="TLS certificates from PCAP",
    select_impl=select_pcap_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
