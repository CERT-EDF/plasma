"""Linux Module Cross View Memory Dissector"""

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

_VOL_PLUGIN = 'linux.malware.modxview.Modxview'
_VOL_FIELDS_MAPPING = {
    'Address': 'address',
    'Name': 'module',
    'In procfs': 'in_procfs',
    'In scan': 'in_scan',
    'In sysfs': 'in_sysfs',
    'Taints': 'taints',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_modxview',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('address', DataType.STR),
        Column('module', DataType.STR),
        Column('in_procfs', DataType.BOOL),
        Column('in_scan', DataType.BOOL),
        Column('in_sysfs', DataType.BOOL),
        Column('taints', DataType.STR),
    ],
    description="Linux modules cross view from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
