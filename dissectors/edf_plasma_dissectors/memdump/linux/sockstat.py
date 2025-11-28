"""Linux Network Connections Memory Dissector"""

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

_VOL_PLUGIN = 'linux.sockstat.Sockstat'
_VOL_FIELDS_MAPPING = {
    'PID': 'pid',
    'TID': 'tid',
    'Process Name': 'process',
    'Source Addr': 'src_addr',
    'Source Port': 'src_port',
    'Destination Addr': 'dst_addr',
    'Destination Port': 'dst_port',
    'Family': 'family',
    'Proto': 'proto',
    'State': 'state',
    'Type': 'type',
    'FD': 'fd',
    'Filter': 'filter',
    'NetNS': 'net_ns',
    'Sock Offset': 'sock_offset',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_sockstat',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('pid', DataType.INT),
        Column('tid', DataType.INT),
        Column('process', DataType.STR),
        Column('src_addr', DataType.STR),
        Column('src_port', DataType.STR),
        Column('dst_addr', DataType.STR),
        Column('dst_port', DataType.STR),
        Column('family', DataType.STR),
        Column('proto', DataType.STR),
        Column('state', DataType.STR),
        Column('type', DataType.STR),
        Column('fd', DataType.INT),
        Column('filter', DataType.STR),
        Column('net_ns', DataType.INT),
        Column('sock_offset', DataType.INT),
    ],
    description="Linux network connections from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
