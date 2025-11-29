"""Windows Drivers Memory Dissector"""

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

_VOL_PLUGIN = 'windows.driverscan.DriverScan'
_VOL_FIELDS_MAPPING = {
    'Driver Name': 'driver_name',
    'Name': 'name',
    'Offset': 'offset',
    'Service Key': 'service_key',
    'Size': 'size',
    'Start': 'start',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_drv_scan',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('driver_name', DataType.STR),
        Column('name', DataType.STR),
        Column('offset', DataType.INT),
        Column('service_key', DataType.STR),
        Column('size', DataType.INT),
        Column('start', DataType.INT),
    ],
    description="Windows drivers (carved) from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
