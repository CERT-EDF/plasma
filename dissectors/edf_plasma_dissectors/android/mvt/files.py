"""MVT Android Files artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.json import read_json
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob('files.json'):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    records = read_json(ctx.filepath)
    if records is None:
        ctx.register_error(f"failed to load JSON data from: {ctx.filepath}")
        return
    for record in records:
        if not isinstance(record, dict):
            ctx.register_error(f"unsupported format: {ctx.filepath}")
            return
        yield {
            'file_mtime': record['modified_time'],
            'file_path': record['path'],
            'file_mode': record['mode'],
            'file_is_suid': record['is_suid'],
            'file_is_sgid': record['is_sgid'],
            'file_size': record['size'],
            'file_owner': record['owner'],
            'file_group': record['group'],
        }


DISSECTOR = Dissector(
    slug='android_mvt_files',
    tags={Tag.MVT, Tag.ANDROID},
    columns=[
        Column('file_mtime', DataType.STR),
        Column('file_path', DataType.STR),
        Column('file_mode', DataType.STR),
        Column('file_is_suid', DataType.BOOL),
        Column('file_is_sgid', DataType.BOOL),
        Column('file_size', DataType.INT),
        Column('file_owner', DataType.STR),
        Column('file_group', DataType.STR),
    ],
    description="MVT Android files output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
