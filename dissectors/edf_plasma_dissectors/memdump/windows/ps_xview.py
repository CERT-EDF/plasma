"""Windows Processes Cross View Memory Dissector"""

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

_VOL_PLUGIN = 'windows.malware.psxview.PsXView'
_VOL_FIELDS_MAPPING = {
    'PID': 'pid',
    'Name': 'process',
    'Exit Time': 'exit_time',
    'Offset(Virtual)': 'virt_offset',
    'csrss': 'in_csrss',
    'pslist': 'in_ps_list',
    'psscan': 'in_ps_scan',
    'thrdscan': 'in_thrd_scan',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_ps_xview',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('pid', DataType.INT),
        Column('process', DataType.STR),
        Column('exit_time', DataType.STR),
        Column('virt_offset', DataType.INT),
        Column('in_csrss', DataType.BOOL),
        Column('in_ps_list', DataType.BOOL),
        Column('in_ps_scan', DataType.BOOL),
        Column('in_thrd_scan', DataType.BOOL),
    ],
    description="Windows TODO from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
