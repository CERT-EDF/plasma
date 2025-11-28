"""Linux Open Files List Memory Dissector"""

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

_VOL_PLUGIN = 'linux.lsof.Lsof'
_VOL_FIELDS_MAPPING = {
    'PID': 'pid',
    'Process': 'process',
    'TID': 'tid',
    'FD': 'fd',
    'Inode': 'inode',
    'Modified': 'modified',
    'Accessed': 'accessed',
    'Changed': 'changed',
    'Device': 'device',
    'Type': 'type',
    'Size': 'size',
    'Mode': 'mode',
    'Path': 'filepath',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_lsof',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('pid', DataType.INT),
        Column('process', DataType.STR),
        Column('tid', DataType.INT),
        Column('fd', DataType.INT),
        Column('inode', DataType.INT),
        Column('modified', DataType.STR),
        Column('accessed', DataType.STR),
        Column('changed', DataType.STR),
        Column('device', DataType.STR),
        Column('type', DataType.STR),
        Column('size', DataType.INT),
        Column('mode', DataType.STR),
        Column('filepath', DataType.STR),
    ],
    description="Linux open files list from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
