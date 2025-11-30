"""Linux Processes Maps Memory Dissector"""

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

_VOL_PLUGIN = 'linux.proc.Maps'
_VOL_FIELDS_MAPPING = {
    'PID': 'pid',
    'Process': 'process',
    'Flags': 'flags',
    'Inode': 'inode',
    'File Path': 'filepath',
    'Major': 'sb_major',
    'Minor': 'sb_minor',
    'PgOff': 'page_offset',
    'Start': 'vm_start',
    'End': 'vm_end',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_proc_maps',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('pid', DataType.INT),
        Column('process', DataType.STR),
        Column('flags', DataType.STR),
        Column('inode', DataType.INT),
        Column('filepath', DataType.STR),
        Column('sb_major', DataType.INT),
        Column('sb_minor', DataType.INT),
        Column('page_offset', DataType.INT),
        Column('vm_start', DataType.INT),
        Column('vm_end', DataType.INT),
    ],
    description="Linux processes maps from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
