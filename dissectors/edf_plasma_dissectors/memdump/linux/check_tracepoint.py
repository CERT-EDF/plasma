"""Linux Check Tracepoints Memory Dissector"""

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

_VOL_PLUGIN = 'linux.tracing.tracepoints.CheckTracepoints'
_VOL_FIELDS_MAPPING = {
    'Module': 'module',
    'Module address': 'module_addr',
    'Probe': 'probe',
    'Probe address': 'probe_addr',
    'Probe priority': 'probe_priority',
    'tracepoint': 'tracepoint',
    'tracepoint address': 'tracepoint_addr',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_check_tracepoint',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('module', DataType.STR),
        Column('module_addr', DataType.INT),
        Column('probe', DataType.STR),
        Column('probe_addr', DataType.INT),
        Column('probe_priority', DataType.INT),
        Column('tracepoint', DataType.STR),
        Column('tracepoint_addr', DataType.INT),
    ],
    description="Linux check tracepoints from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
