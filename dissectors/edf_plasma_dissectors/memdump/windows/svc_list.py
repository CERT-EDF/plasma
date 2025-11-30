"""Windows Services Memory Dissector"""

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

_VOL_PLUGIN = 'windows.svclist.SvcList'
_VOL_FIELDS_MAPPING = {
    'Binary': 'binary',
    'Binary (Registry)': 'binary_registry',
    'Display': 'display',
    'Dll': 'dll',
    'Name': 'name',
    'Offset': 'offset',
    'Order': 'order',
    'PID': 'pid',
    'Start': 'start',
    'State': 'state',
    'Type': 'type',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_svc_list',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('binary', DataType.STR),
        Column('binary_registry', DataType.STR),
        Column('display', DataType.STR),
        Column('dll', DataType.STR),
        Column('name', DataType.STR),
        Column('offset', DataType.INT),
        Column('order', DataType.INT),
        Column('pid', DataType.INT),
        Column('start', DataType.STR),
        Column('state', DataType.STR),
        Column('type', DataType.STR),
    ],
    description="Windows services from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
