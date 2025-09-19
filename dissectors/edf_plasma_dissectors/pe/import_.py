"""PE import dissector"""

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
    for import_ in pef.imports:
        for entry in import_.entries:
            yield {
                'pe_sha256': digest,
                'pe_i_lib': import_.name.lower(),
                'pe_i_fun': entry.name,
                'pe_i_delayed': False,
            }
    for delay_import in pef.delay_imports:
        for entry in delay_import.entries:
            yield {
                'pe_sha256': digest,
                'pe_i_lib': delay_import.name.lower(),
                'pe_i_fun': entry.name,
                'pe_i_delayed': True,
            }


DISSECTOR = Dissector(
    slug='pe_import',
    tags={Tag.WINDOWS, Tag.PE},
    columns=[
        Column('pe_sha256', DataType.STR),
        Column('pe_i_lib', DataType.STR),
        Column('pe_i_fun', DataType.STR),
        Column('pe_i_delayed', DataType.BOOL),
    ],
    description="PE imported symbols",
    select_impl=select_pe_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
