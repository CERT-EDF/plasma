"""Windows Memory Proces List Dissector"""

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


_VOL_PLUGIN = 'windows.pslist.PsList'
_VOL_FIELDS_MAPPING = {
    'PID': 'pid',
    'PPID': 'ppid',
    'ImageFileName': 'image',
    'Offset(V)': 'virt_offset',
    'Threads': 'threads',
    'Handles': 'handles',
    'SessionId': 'session_id',
    'Wow64': 'wow64',
    'CreateTime': 'create_time',
    'ExitTime': 'exit_time',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memory_windows_pslist',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('pid', DataType.INT),
        Column('ppid', DataType.INT),
        Column('image', DataType.STR),
        Column('virt_offset', DataType.INT),
        Column('threads', DataType.INT),
        Column('handles', DataType.INT),
        Column('session_id', DataType.INT),
        Column('wow64', DataType.BOOL),
        Column('create_time', DataType.STR),
        Column('exit_time', DataType.STR),
    ],
    description="Windows process list from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
