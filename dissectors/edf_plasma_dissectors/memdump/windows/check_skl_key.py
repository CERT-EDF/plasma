"""Windows Check Skeleton Key Memory Dissector"""

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

_VOL_PLUGIN = 'windows.malware.skeleton_key_check.Skeleton_Key_Check'
_VOL_FIELDS_MAPPING = {
    'PID': 'pid',
    'Process': 'process',
    'Skeleton Key Found': 'skeleton_key_found',
    'rc4HmacDecrypt': 'rc4_hmac_decrypt',
    'rc4HmacInitialize': 'rc4_hmac_init',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_check_skl_key',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('pid', DataType.INT),
        Column('process', DataType.STR),
        Column('skeleton_key_found', DataType.BOOL),
        Column('rc4_hmac_decrypt', DataType.INT),
        Column('rc4_hmac_init', DataType.INT),
    ],
    description="Windows check skeleton key from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
