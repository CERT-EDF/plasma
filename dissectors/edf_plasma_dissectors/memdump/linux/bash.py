"""Linux Bash Commands Memory Dissector"""

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

_VOL_PLUGIN = 'linux.bash.Bash'
_VOL_FIELDS_MAPPING = {
    'CommandTime': 'time',
    'PID': 'pid',
    'Process': 'process',
    'Command': 'command',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_bash',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('time', DataType.STR),
        Column('pid', DataType.INT),
        Column('process', DataType.STR),
        Column('command', DataType.STR),
    ],
    description="Linux bash commands from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
