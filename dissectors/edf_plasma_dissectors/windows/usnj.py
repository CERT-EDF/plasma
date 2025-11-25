"""Windows $UsnJrnl:$J artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

from .parser.usnj import usnj_records


def _select_impl(directory: Path) -> PathIterator:
    pattern = ci_glob_pattern('$UsnJrnl*$J')
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    yield from usnj_records(ctx)


DISSECTOR = Dissector(
    slug='windows_usnj',
    tags={Tag.WINDOWS},
    columns=[
        Column('usnj_time', DataType.STR),
        Column('usnj_reason', DataType.STR),
        Column('usnj_source', DataType.STR),
        Column('usnj_filename', DataType.STR),
        Column('usnj_file_flags', DataType.STR),
        Column('usnj_mft_seq_num', DataType.INT),
        Column('usnj_mft_ent_num', DataType.INT),
        Column('usnj_mft_parent_seq_num', DataType.INT),
        Column('usnj_mft_parent_ent_num', DataType.INT),
    ],
    description="NTFS USN journal",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
