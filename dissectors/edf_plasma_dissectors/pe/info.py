"""PE information dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.hashing import (
    HashingAlgorithm,
    digest_from_filepath,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from .helper import (
    parse_pe,
    pe_imphash,
    pe_pdb,
    pe_sig_check,
    pe_version,
    select_pe_impl,
)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    pef = parse_pe(ctx)
    yield {
        'pe_md5': digest_from_filepath(HashingAlgorithm.MD5, ctx.filepath),
        'pe_sha1': digest_from_filepath(HashingAlgorithm.SHA1, ctx.filepath),
        'pe_sha256': digest_from_filepath(
            HashingAlgorithm.SHA256, ctx.filepath
        ),
        'pe_imphash': pe_imphash(pef),
        'pe_version': pe_version(pef),
        'pe_size': ctx.filepath.stat().st_size,
        'pe_filename': ctx.filepath.name,
        'pe_is_pie': pef.is_pie,
        'pe_entrypoint': f'{pef.entrypoint:#018x}',
        'pe_sig_check': pe_sig_check(pef),
        'pe_pdb': pe_pdb(pef),
    }


DISSECTOR = Dissector(
    slug='pe_info',
    tags={Tag.WINDOWS, Tag.PE},
    columns=[
        Column('pe_md5', DataType.STR),
        Column('pe_sha1', DataType.STR),
        Column('pe_sha256', DataType.STR),
        Column('pe_imphash', DataType.STR),
        Column('pe_version', DataType.STR),
        Column('pe_size', DataType.INT),
        Column('pe_filename', DataType.STR),
        Column('pe_is_pie', DataType.BOOL),
        Column('pe_entrypoint', DataType.STR),
        Column('pe_sig_check', DataType.STR),
        Column('pe_pdb', DataType.STR),
    ],
    description="PE information",
    select_impl=select_pe_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
