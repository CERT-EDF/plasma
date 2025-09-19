"""PE export dissector"""

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

from .helper import parse_pe, select_pe_impl


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    pef = parse_pe(ctx)
    digest = digest_from_filepath(HashingAlgorithm.SHA256, ctx.filepath)
    export = pef.get_export()
    for entry in export.entries:
        yield {
            'pe_sha256': digest,
            'pe_e_name': entry.name,
            'pe_e_ordinal': entry.ordinal,
            'pe_e_address': f'{entry.address:#018x}',
        }


DISSECTOR = Dissector(
    slug='pe_export',
    tags={Tag.WINDOWS, Tag.PE},
    columns=[
        Column('pe_sha256', DataType.STR),
        Column('pe_e_name', DataType.STR),
        Column('pe_e_ordinal', DataType.INT),
        Column('pe_e_address', DataType.STR),
    ],
    description="PE exported symbols",
    select_impl=select_pe_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
