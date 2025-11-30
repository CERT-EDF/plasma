"""Windows Unloaded Modules Memory Dissector"""

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

_VOL_PLUGIN = 'windows.unloadedmodules.UnloadedModules'
_VOL_FIELDS_MAPPING = {
    'Name': 'name',
    'StartAddress': 'start_addr',
    'EndAddress': 'end_addr',
    'Time': 'time',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_mod_list_unloaded',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('name', DataType.STR),
        Column('start_addr', DataType.INT),
        Column('end_addr', DataType.INT),
        Column('time', DataType.STR),
    ],
    description="Windows unloaded modules from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
