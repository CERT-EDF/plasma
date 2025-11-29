"""Windows Sessions Memory Dissector"""

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

_VOL_PLUGIN = 'windows.sessions.Sessions'
_VOL_FIELDS_MAPPING = {
    'Process ID': 'pid',
    'Process': 'process',
    'Create Time': 'create_time',
    'Session ID': 'session_id',
    'Session Type': 'session_type',
    'User Name': 'username',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_sessions',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('pid', DataType.INT),
        Column('process', DataType.STR),
        Column('create_time', DataType.STR),
        Column('session_id', DataType.STR),
        Column('session_type', DataType.STR),
        Column('username', DataType.STR),
    ],
    description="Windows sessions from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
