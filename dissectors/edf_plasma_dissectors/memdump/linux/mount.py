"""Linux Mount Info Memory Dissector"""

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

_VOL_PLUGIN = 'linux.mountinfo.MountInfo'
_VOL_FIELDS_MAPPING = {
    'FIELDS': 'fields',
    'FSTYPE': 'fstype',
    'MAJOR:MINOR': 'st_rdev',
    'MNT_NS_ID': 'mount_ns_id',
    'MOUNT ID': 'mount_id',
    'MOUNT_OPTIONS': 'mount_opts',
    'MOUNT_POINT': 'mount_point',
    'MOUNT_SRC': 'mount_src',
    'PARENT_ID': 'parent_id',
    'ROOT': 'root',
    'SB_OPTIONS': 'sb_opts',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_linux_mount',
    tags={Tag.MEMDUMP, Tag.LINUX},
    columns=[
        Column('fields', DataType.STR),
        Column('fstype', DataType.STR),
        Column('st_rdev', DataType.STR),
        Column('mount_ns_id', DataType.INT),
        Column('mount_id', DataType.INT),
        Column('mount_opts', DataType.STR),
        Column('mount_point', DataType.STR),
        Column('mount_src', DataType.STR),
        Column('parent_id', DataType.INT),
        Column('root', DataType.STR),
        Column('sb_opts', DataType.STR),
    ],
    description="Linux mount from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
