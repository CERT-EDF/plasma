"""Windows Libraries Memory Dissector"""

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

_VOL_PLUGIN = 'windows.dlllist.DllList'
_VOL_FIELDS_MAPPING = {
    'PID': 'pid',
    'Process': 'process',
    'Base': 'base',
    'LoadTime': 'load_time',
    'Name': 'filename',
    'Path': 'filepath',
    'Size': 'size',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_liblist',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('pid', DataType.INT),
        Column('process', DataType.STR),
        Column('base', DataType.INT),
        Column('load_time', DataType.STR),
        Column('filename', DataType.STR),
        Column('filepath', DataType.STR),
        Column('size', DataType.STR),
    ],
    description="Windows libraries from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
