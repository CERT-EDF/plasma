"""Windows Processes Memory Dissector"""

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

_VOL_PLUGIN = 'windows.psscan.PsScan'
_VOL_FIELDS_MAPPING = {
    'PID': 'pid',
    'PPID': 'ppid',
    'ImageFileName': 'process',
    'CreateTime': 'create_time',
    'ExitTime': 'exit_time',
    'Handles': 'handles',
    'Offset(V)': 'virt_offset',
    'SessionId': 'session_id',
    'Threads': 'threads',
    'Wow64': 'wow64',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_ps_scan',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('pid', DataType.INT),
        Column('ppid', DataType.INT),
        Column('process', DataType.STR),
        Column('create_time', DataType.STR),
        Column('exit_time', DataType.STR),
        Column('handles', DataType.STR),
        Column('virt_offset', DataType.INT),
        Column('session_id', DataType.STR),
        Column('threads', DataType.INT),
        Column('wow64', DataType.BOOL),
    ],
    description="Windows processes (carved) from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
