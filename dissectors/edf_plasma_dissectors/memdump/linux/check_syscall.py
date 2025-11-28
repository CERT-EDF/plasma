"""Linux Check Syscall Memory Dissector"""

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

_VOL_PLUGIN = 'linux.malware.check_syscall.Check_syscall'
_VOL_FIELDS_MAPPING = {
    'Handler Address': 'handler_addr',
    'Handler Symbol': 'handler_symbol',
    'Index': 'index',
    'Table Address': 'table_addr',
    'Table Name': 'table_name',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_check_syscall',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('handler_addr', DataType.INT),
        Column('handler_symbol', DataType.STR),
        Column('index', DataType.INT),
        Column('table_addr', DataType.INT),
        Column('table_name', DataType.STR),
    ],
    description="Linux check syscall from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
