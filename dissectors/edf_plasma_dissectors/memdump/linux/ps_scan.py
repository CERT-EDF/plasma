"""Linux Processes (Carved) Memory Dissector"""

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

_VOL_PLUGIN = 'linux.psscan.PsScan'
_VOL_FIELDS_MAPPING = {
    'COMM': 'process',
    'EXIT_STATE': 'exit_state',
    'OFFSET (P)': 'phys_offset',
    'PID': 'pid',
    'PPID': 'ppid',
    'TID': 'tid',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_ps_scan',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('pid', DataType.INT),
        Column('ppid', DataType.INT),
        Column('tid', DataType.INT),
        Column('process', DataType.STR),
        Column('exit_state', DataType.STR),
        Column('phys_offset', DataType.INT),
    ],
    description="Linux processes (carved) from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
