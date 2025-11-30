"""Linux VM Core Info Memory Dissector"""

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

_VOL_PLUGIN = 'linux.vmcoreinfo.VMCoreInfo'
_VOL_FIELDS_MAPPING = {
    'Offset': 'offset',
    'Key': 'key',
    'Value': 'value',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_vmcore',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('offset', DataType.INT),
        Column('key', DataType.STR),
        Column('value', DataType.STR),
    ],
    description="Linux vmcore info from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
