"""Windows LNK artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

from .helper.lnk import check_file_signature, open_file_object
from .parser.lnk import lnk_records

_LOGGER = get_logger('dissectors.windows.lnk')


def _select_impl(directory: Path) -> PathIterator:
    pattern = ci_glob_pattern('*.lnk')
    for filepath in select(directory, pattern):
        if not check_file_signature(filepath):
            _LOGGER.warning("link signature check failed: %s", filepath)
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open('rb') as fobj:
        lnk_obj = open_file_object(fobj)
        yield from lnk_records(lnk_obj)


DISSECTOR = Dissector(
    slug='windows_lnk',
    tags={Tag.WINDOWS},
    columns=[
        Column('lnk_time', DataType.STR),
        Column('lnk_macb', DataType.STR),
        Column('lnk_desc', DataType.STR),
        Column('lnk_drive_sn', DataType.INT),
        Column('lnk_drive_type', DataType.INT),
        Column('lnk_target', DataType.STR),
        Column('lnk_target_sz', DataType.INT),
        Column('lnk_target_attrib', DataType.STR),
        Column('lnk_workdir', DataType.STR),
        Column('lnk_net_loc', DataType.STR),
        Column('lnk_env_loc', DataType.STR),
        Column('lnk_icon_loc', DataType.STR),
        Column('lnk_machine_id', DataType.STR),
        Column('lnk_vol_label', DataType.STR),
    ],
    description="LNK",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
