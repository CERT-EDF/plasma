"""Windows Connections Memory Dissector"""

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

_VOL_PLUGIN = 'windows.netstat.NetStat'
_VOL_FIELDS_MAPPING = {
    'PID': 'pid',
    'Owner': 'process',
    'LocalAddr': 'src_addr',
    'LocalPort': 'src_port',
    'ForeignAddr': 'dst_addr',
    'ForeignPort': 'dst_port',
    'Created': 'created',
    'Offset': 'offset',
    'Proto': 'proto',
    'State': 'state',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_netstat',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('pid', DataType.INT),
        Column('process', DataType.STR),
        Column('src_addr', DataType.STR),
        Column('src_port', DataType.INT),
        Column('dst_addr', DataType.STR),
        Column('dst_port', DataType.INT),
        Column('created', DataType.STR),
        Column('offset', DataType.INT),
        Column('proto', DataType.STR),
        Column('state', DataType.STR),
    ],
    description="Windows connections from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
