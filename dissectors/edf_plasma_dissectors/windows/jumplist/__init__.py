"""Windows JumpList artifact dissector"""

from io import BytesIO
from mmap import ACCESS_READ, mmap
from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

from ..lnk.parser import MS_SHLLNK_SIG, parse_lnk_bytes
from .helper import check_file_signature, open_file_object
from .parser import dest_list_entries, parse_lnk_blob

_LOGGER = get_logger('dissectors.microsoft.jumplist')


def _check_custom_destination(filepath: Path) -> bool:
    with filepath.open('rb') as fobj:
        with mmap(fobj.fileno(), 0, access=ACCESS_READ) as mem:
            return mem.find(MS_SHLLNK_SIG) >= 0


def _parse_custom_destination(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open('rb') as fobj:
        with mmap(fobj.fileno(), 0, access=ACCESS_READ) as mem:
            offset = 0
            while True:
                offset = mem.find(MS_SHLLNK_SIG, offset)
                if offset < 0:
                    break
                yield from parse_lnk_bytes(BytesIO(mem[offset:]), ctx)
                offset += 1


def _check_automatic_destination(filepath: Path) -> bool:
    return check_file_signature(str(filepath))


def _parse_automatic_destination(
    ctx: DissectionContext,
) -> RecordIterator:
    with ctx.filepath.open('rb') as fobj:
        try:
            jl_file = open_file_object(fobj)
        except OSError as exc:
            ctx.register_error(f"libolecf exception: {exc}")
            return
        jl_root = jl_file.root_item
        for dest_list_entry in dest_list_entries(jl_root, ctx):
            yield from parse_lnk_blob(jl_root, dest_list_entry.entry_num, ctx)


_CHECK_FUNC_MAP = {
    ci_glob_pattern('*.customDestinations-ms'): _check_custom_destination,
    ci_glob_pattern(
        '*.automaticDestinations-ms'
    ): _check_automatic_destination,
}
_PARSE_FUNC_MAP = {
    '.customdestinations-ms': _parse_custom_destination,
    '.automaticdestinations-ms': _parse_automatic_destination,
}


def _select_impl(directory: Path) -> PathIterator:
    for pattern, check_file_signature_func in _CHECK_FUNC_MAP.items():
        for filepath in directory.rglob(pattern):
            if not filepath.is_file():
                continue
            if not check_file_signature_func(filepath):
                _LOGGER.warning(
                    "jumplist signature check failed: %s", filepath
                )
                continue
            yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    parse_file_func = _PARSE_FUNC_MAP[ctx.filepath.suffix.lower()]
    yield from parse_file_func(ctx)


DISSECTOR = Dissector(
    slug='windows_jumplist',
    tags={Tag.WINDOWS},
    columns=[
        Column('lnk_time', DataType.STR),
        Column('lnk_macb', DataType.STR),
        Column('lnk_desc', DataType.STR),
        Column('lnk_drive_sn', DataType.STR),
        Column('lnk_drive_type', DataType.STR),
        Column('lnk_target', DataType.STR),
        Column('lnk_target_sz', DataType.STR),
        Column('lnk_target_attrib', DataType.STR),
        Column('lnk_workdir', DataType.STR),
        Column('lnk_net_loc', DataType.STR),
        Column('lnk_env_loc', DataType.STR),
        Column('lnk_icon_loc', DataType.STR),
        Column('lnk_machine_id', DataType.STR),
        Column('lnk_vol_label', DataType.STR),
    ],
    description="Jumplist entries",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
