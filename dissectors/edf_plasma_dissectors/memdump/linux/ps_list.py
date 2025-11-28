"""Linux Processes Memory Dissector"""

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

_VOL_PLUGIN = 'linux.pslist.PsList'
_VOL_FIELDS_MAPPING = {
    'OFFSET (V)': 'virt_offset',
    'PID': 'pid',
    'TID': 'tid',
    'PPID': 'ppid',
    'COMM': 'comm',
    'UID': 'uid',
    'GID': 'gid',
    'EUID': 'euid',
    'EGID': 'egid',
    'CREATION TIME': 'create_time',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_ps_list',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('virt_offset', DataType.INT),
        Column('pid', DataType.INT),
        Column('tid', DataType.INT),
        Column('ppid', DataType.INT),
        Column('comm', DataType.STR),
        Column('uid', DataType.INT),
        Column('gid', DataType.INT),
        Column('euid', DataType.INT),
        Column('egid', DataType.INT),
        Column('create_time', DataType.STR),
    ],
    description="Linux processes from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
