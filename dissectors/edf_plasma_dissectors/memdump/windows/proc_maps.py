"""Windows Processes Maps Memory Dissector"""

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

_VOL_PLUGIN = 'windows.vadinfo.VadInfo'
_VOL_FIELDS_MAPPING = {
    'PID': 'pid',
    'Process': 'process',
    'Offset': 'offset',
    'Start VPN': 'start_vpn',
    'End VPN': 'end_vpn',
    'Tag': 'tag',
    'Protection': 'protection',
    'CommitCharge': 'commit_charge',
    'PrivateMemory': 'private_mem',
    'Parent': 'parent',
    'File': 'file',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_proc_maps',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('pid', DataType.INT),
        Column('process', DataType.STR),
        Column('offset', DataType.INT),
        Column('start_vpn', DataType.INT),
        Column('end_vpn', DataType.INT),
        Column('tag', DataType.STR),
        Column('protection', DataType.STR),
        Column('commit_charge', DataType.INT),
        Column('private_mem', DataType.INT),
        Column('parent', DataType.INT),
        Column('file', DataType.STR),
    ],
    description="Windows processes maps from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
