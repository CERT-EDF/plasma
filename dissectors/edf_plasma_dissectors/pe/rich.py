"""PE rich dissector"""

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
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from .helper import parse_pe, select_pe_impl

_LOGGER = get_logger('dissectors.pe.rich')


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    pef = parse_pe(ctx)
    digest = digest_from_filepath(HashingAlgorithm.SHA256, ctx.filepath)
    if pef.rich_header is None:
        _LOGGER.warning("portable executable does not have any rich header")
        return
    for entry in pef.rich_header.entries:
        yield {
            'pe_sha256': digest,
            'pe_h_build': entry.build_id,
            'pe_h_prodid': entry.id,
            'pe_h_count': entry.count,
        }


DISSECTOR = Dissector(
    slug='pe_rich',
    tags={Tag.WINDOWS, Tag.PE},
    columns=[
        Column('pe_sha256', DataType.STR),
        Column('pe_h_build', DataType.INT),
        Column('pe_h_prodid', DataType.INT),
        Column('pe_h_count', DataType.INT),
    ],
    description="PE rich header",
    select_impl=select_pe_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
