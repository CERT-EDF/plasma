"""Linux Module List Memory Dissector"""

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

_VOL_PLUGIN = 'linux.lsmod.Lsmod'
_VOL_FIELDS_MAPPING = {
    'Code Size': 'code_size',
    'Load Arguments': 'arguments',
    'Module Name': 'module',
    'Offset': 'offset',
    'Taints': 'taints',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_lsmod',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('code_size', DataType.INT),
        Column('offset', DataType.INT),
        Column('module', DataType.STR),
        Column('arguments', DataType.STR),
        Column('taints', DataType.STR),
    ],
    description="Linux module list from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
