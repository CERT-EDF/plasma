"""PE signature dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import datetime, to_iso_fmt, with_utc
from edf_plasma_core.helper.hashing import (
    HashingAlgorithm,
    digest_from_filepath,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from .helper import parse_pe, pe_certificate_key_type, select_pe_impl


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    pef = parse_pe(ctx)
    digest = digest_from_filepath(HashingAlgorithm.SHA256, ctx.filepath)
    for signature in pef.signatures:
        *_, certificate = signature.certificates
        valid_after = to_iso_fmt(with_utc(datetime(*certificate.valid_from)))
        valid_until = to_iso_fmt(with_utc(datetime(*certificate.valid_to)))
        yield {
            'pe_sha256': digest,
            'pe_crt_version': str(certificate.version),
            'pe_crt_is_ca': certificate.is_ca,
            'pe_crt_sn': certificate.serial_number.hex(),
            'pe_crt_issuer': str(certificate.issuer),
            'pe_crt_subject': str(certificate.subject),
            'pe_crt_key_type': pe_certificate_key_type(certificate),
            'pe_crt_key_size': certificate.rsa_info.key_size,
            'pe_crt_valid_after': valid_after,
            'pe_crt_valid_until': valid_until,
            'pe_crt_sig_algo': str(certificate.signature_algorithm),
            'pe_crt_ext_key_usage': str(certificate.ext_key_usage),
            'pe_crt_policies': str(certificate.certificate_policies),
        }


DISSECTOR = Dissector(
    slug='pe_signature',
    tags={Tag.WINDOWS, Tag.PE},
    columns=[
        Column('pe_sha256', DataType.STR),
        Column('pe_crt_version', DataType.STR),
        Column('pe_crt_is_ca', DataType.BOOL),
        Column('pe_crt_sn', DataType.STR),
        Column('pe_crt_issuer', DataType.STR),
        Column('pe_crt_subject', DataType.STR),
        Column('pe_crt_key_type', DataType.STR),
        Column('pe_crt_key_size', DataType.INT),
        Column('pe_crt_valid_after', DataType.STR),
        Column('pe_crt_valid_until', DataType.STR),
        Column('pe_crt_sig_algo', DataType.STR),
        Column('pe_crt_ext_key_usage', DataType.STR),
        Column('pe_crt_policies', DataType.STR),
    ],
    description="PE signatures",
    select_impl=select_pe_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
