"""Windows Threads Memory Dissector"""

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

_VOL_PLUGIN = 'windows.threads.Threads'
_VOL_FIELDS_MAPPING = {
    'PID': 'pid',
    'TID': 'tid',
    'CreateTime': 'create_time',
    'ExitTime': 'exit_time',
    'Offset': 'offset',
    'StartAddress': 'start_addr',
    'StartPath': 'start_path',
    'Win32StartAddress': 'win32_start_addr',
    'Win32StartPath': 'win32_start_path',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_thrd_list',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('pid', DataType.INT),
        Column('tid', DataType.INT),
        Column('create_time', DataType.STR),
        Column('exit_time', DataType.STR),
        Column('offset', DataType.INT),
        Column('start_addr', DataType.INT),
        Column('start_path', DataType.STR),
        Column('win32_start_addr', DataType.INT),
        Column('win32_start_path', DataType.STR),
    ],
    description="Windows Threads from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
