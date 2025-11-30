"""Windows Virtual Map Memory Dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from ..helper import (
    run_volatility3_plugin,
    select_memdump_impl,
    setup_volatility3_framework,
)

_VOL_PLUGIN = 'windows.virtmap.VirtMap'
_VOL_FIELDS_MAPPING = {
    'Region': 'region',
    'Start offset': 'start_offset',
    'End offset': 'end_offset',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_virtmap',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('region', DataType.STR),
        Column('start_offset', DataType.INT),
        Column('end_offset', DataType.INT),
    ],
    description="Windows virtual map from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
