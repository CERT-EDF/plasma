"""Windows Check Libraries Memory Dissector"""

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

_VOL_PLUGIN = 'windows.malware.ldrmodules.LdrModules'
_VOL_FIELDS_MAPPING = {
    'Pid': 'pid',
    'Process': 'process',
    'Base': 'base',
    'InInit': 'in_init',
    'InLoad': 'in_load',
    'InMem': 'in_mem',
    'MappedPath': 'mapped_path',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_check_lib',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('pid', DataType.INT),
        Column('process', DataType.STR),
        Column('base', DataType.INT),
        Column('in_init', DataType.BOOL),
        Column('in_load', DataType.BOOL),
        Column('in_mem', DataType.BOOL),
        Column('mapped_path', DataType.STR),
    ],
    description="Windows check libraries from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
