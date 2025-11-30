"""Linux Check Netfilter Memory Dissector"""

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

_VOL_PLUGIN = 'linux.malware.netfilter.Netfilter'
_VOL_FIELDS_MAPPING = {
    'Handler': 'handler_addr',
    'Hook': 'hook',
    'Is Hooked': 'is_hooked',
    'Module': 'module',
    'Net NS': 'net_ns',
    'Priority': 'priority',
    'Proto': 'proto',
    'Symbol': 'symbol',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_check_nf',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('handler_addr', DataType.INT),
        Column('hook', DataType.STR),
        Column('is_hooked', DataType.BOOL),
        Column('module', DataType.STR),
        Column('net_ns', DataType.INT),
        Column('priority', DataType.INT),
        Column('proto', DataType.STR),
        Column('symbol', DataType.STR),
    ],
    description="Linux check netfilter from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
