"""Windows Amcache Memory Dissector"""

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

_VOL_PLUGIN = 'windows.registry.amcache.Amcache'
_VOL_FIELDS_MAPPING = {
    'EntryType': 'entry_type',
    'Path': 'path',
    'Company': 'company',
    'LastModifyTime': 'reg_key_mod_time',
    'LastModifyTime2': 'std_info_mod_time',
    'CompileTime': 'compile_time',
    'InstallTime': 'install_time',
    'SHA1': 'sha1',
    'Service': 'service',
    'ProductName': 'product_name',
    'ProductVersion': 'product_version',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_amcache',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('entry_type', DataType.STR),
        Column('path', DataType.STR),
        Column('company', DataType.STR),
        Column('reg_key_mod_time', DataType.STR),
        Column('std_info_mod_time', DataType.STR),
        Column('compile_time', DataType.STR),
        Column('install_time', DataType.STR),
        Column('sha1', DataType.STR),
        Column('service', DataType.STR),
        Column('product_name', DataType.STR),
        Column('product_version', DataType.STR),
    ],
    description="Windows amcache from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
