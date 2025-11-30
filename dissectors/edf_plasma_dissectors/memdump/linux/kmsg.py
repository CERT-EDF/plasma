"""Linux Kernel Messages Memory Dissector"""

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

_VOL_PLUGIN = 'linux.kmsg.Kmsg'
_VOL_FIELDS_MAPPING = {
    'timestamp': 'timestamp',
    'caller': 'caller',
    'facility': 'facility',
    'level': 'level',
    'line': 'line',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_kmsg',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('timestamp', DataType.STR),
        Column('caller', DataType.STR),
        Column('facility', DataType.STR),
        Column('level', DataType.STR),
        Column('line', DataType.STR),
    ],
    description="Linux kernel messages from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
