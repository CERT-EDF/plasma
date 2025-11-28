"""Linux IP Link Memory Dissector"""

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

_VOL_PLUGIN = 'linux.ip.Link'
_VOL_FIELDS_MAPPING = {
    'Interface': 'interface',
    'State': 'state',
    'Flags': 'flags',
    'MAC': 'mac',
    'MTU': 'mtu',
    'NS': 'ns',
    'Qdisc': 'qdisc',
    'Qlen': 'qlen',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_ip_link',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('interface', DataType.STR),
        Column('state', DataType.STR),
        Column('flags', DataType.STR),
        Column('mac', DataType.INT),
        Column('mtu', DataType.INT),
        Column('ns', DataType.STR),
        Column('qdisc', DataType.INT),
        Column('qlen', DataType.STR),
    ],
    description="Linux IP link from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
