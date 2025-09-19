"""Jumplist parsing module"""

from io import BytesIO

from construct import (
    Bytes,
    Int16ul,
    Int32ul,
    Int64ul,
    StreamError,
    Struct,
    Switch,
)
from edf_plasma_core.dissector import DissectionContext

from ..lnk.parser import parse_lnk_bytes

DestListHeader = Struct(
    'version' / Int32ul,
    'entry_count' / Int32ul,
    'pinned_entry_count' / Int32ul,
    'unknown_01' / Int32ul,
    'unknown_02' / Int32ul,
    'unknown_03' / Int32ul,
    'unknown_04' / Int32ul,
    'unknown_05' / Int32ul,
)
DestListEntryV1 = Struct(
    'unknown_01' / Int64ul,
    'droid_vol_id' / Bytes(16),
    'droid_file_id' / Bytes(16),
    'birth_droid_vol_id' / Bytes(16),
    'birth_droid_file_id' / Bytes(16),
    'hostname' / Bytes(16),
    'entry_num' / Int32ul,
    'unknown_02' / Int32ul,
    'unknown_03' / Int32ul,
    'last_modification_timestamp' / Int64ul,
    'pin_status' / Int32ul,
    'path_sz' / Int16ul,
    'path' / Bytes(lambda this: this.path_sz * 2),
)
DestListEntryV2 = Struct(
    'unknown_01' / Int64ul,
    'droid_vol_id' / Bytes(16),
    'droid_file_id' / Bytes(16),
    'birth_droid_vol_id' / Bytes(16),
    'birth_droid_file_id' / Bytes(16),
    'hostname' / Bytes(16),
    'entry_num' / Int32ul,
    'unknown_02' / Int32ul,
    'unknown_03' / Int32ul,
    'last_modification_timestamp' / Int64ul,
    'pin_status' / Int32ul,
    'unknown_04' / Int32ul,
    'unknown_05' / Int32ul,
    'unknown_06' / Int64ul,
    'path_sz' / Int16ul,
    'path' / Bytes(lambda this: this.path_sz * 2),
    'unknown_07' / Int32ul,
)
DestList = Struct(
    'header' / DestListHeader,
    'entries'
    / Switch(
        lambda this: this.header.version,
        {
            1: DestListEntryV1[lambda this: this.header.entry_count],
            2: DestListEntryV2[lambda this: this.header.entry_count],
            3: DestListEntryV2[lambda this: this.header.entry_count],
            4: DestListEntryV2[lambda this: this.header.entry_count],
        },
    ),
)


def dest_list_entries(jl_root, ctx: DissectionContext):
    if jl_root is None:
        ctx.register_error("cannot find jumplist root item")
        return
    dest_list_stream = jl_root.get_sub_item_by_name('DestList')
    dest_list_stream_sz = dest_list_stream.get_size()
    dest_list_bytes = dest_list_stream.read(dest_list_stream_sz)
    try:
        dest_list = DestList.parse(dest_list_bytes)
    except StreamError:
        ctx.register_error("jumplist dest list header is inconsistent")
        return
    for dest_list_entry in dest_list.entries:
        yield dest_list_entry


def parse_lnk_blob(jl_root, entry_num, ctx: DissectionContext):
    dest_list_entry_stream = jl_root.get_sub_item_by_name(str(entry_num))
    if dest_list_entry_stream is None:
        ctx.register_error(
            f"cannot find jumplist sub-item with entry number: {entry_num}"
        )
        return
    dest_list_entry_stream_sz = dest_list_entry_stream.get_size()
    try:
        dest_list_entry_bytes = dest_list_entry_stream.read(
            dest_list_entry_stream_sz
        )
    except OSError as exc:
        ctx.register_error(f"libolecf exception: {exc}")
        return
    yield from parse_lnk_bytes(BytesIO(dest_list_entry_bytes), ctx)
