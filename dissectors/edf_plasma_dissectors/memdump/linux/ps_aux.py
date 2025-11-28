"""Linux Process Arguments Memory Dissector"""

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

_VOL_PLUGIN = 'linux.psaux.PsAux'
_VOL_FIELDS_MAPPING = {
    'PID': 'pid',
    'PPID': 'ppid',
    'COMM': 'process',
    'ARGS': 'command',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_ps_aux',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('pid', DataType.INT),
        Column('ppid', DataType.INT),
        Column('process', DataType.INT),
        Column('command', DataType.INT),
    ],
    description="Linux process arguments from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
