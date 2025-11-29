"""Windows IAT Memory Dissector"""

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

_VOL_PLUGIN = 'windows.iat.IAT'
_VOL_FIELDS_MAPPING = {
    'PID': 'pid',
    'Name': 'process',
    'Address': 'address',
    'Bound': 'bound',
    'Function': 'function',
    'Library': 'library',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_iat',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('pid', DataType.STR),
        Column('process', DataType.STR),
        Column('address', DataType.INT),
        Column('bound', DataType.BOOL),
        Column('function', DataType.STR),
        Column('library', DataType.STR),
    ],
    description="Windows IAT from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
