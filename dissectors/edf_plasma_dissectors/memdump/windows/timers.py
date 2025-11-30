"""Windows Kernel Timers Memory Dissector"""

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

_VOL_PLUGIN = 'windows.timers.Timers'
_VOL_FIELDS_MAPPING = {
    'DueTime': 'due_time',
    'Module': 'module',
    'Offset': 'offset',
    'Period(ms)': 'period_ms',
    'Routine': 'routine',
    'Signaled': 'signaled',
    'Symbol': 'symbol',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_timers',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('due_time', DataType.STR),
        Column('module', DataType.STR),
        Column('offset', DataType.INT),
        Column('period_ms', DataType.INT),
        Column('routine', DataType.INT),
        Column('signaled', DataType.STR),
        Column('symbol', DataType.STR),
    ],
    description="Windows kernel timers from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
