"""MVT Android App Ops artifact dissector"""

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
    for filepath in directory.rglob('dumpsys_appops.json'):
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
        for perm in record['permissions']:
            for entry in perm['entries']:
                yield {
                    'pkg_name': record.get('package_name', ''),
                    'pkg_appop_uid': record.get('uid', ''),
                    'pkg_appop_perm_name': perm.get('name', ''),
                    'pkg_appop_access': entry.get('access', ''),
                    'pkg_appop_type': entry.get('type', ''),
                    'pkg_appop_timestamp': entry.get('timestamp', ''),
                }


DISSECTOR = Dissector(
    slug='android_mvt_appops',
    tags={Tag.MVT, Tag.ANDROID},
    columns=[
        Column('pkg_name', DataType.STR),
        Column('pkg_appop_uid', DataType.STR),
        Column('pkg_appop_perm_name', DataType.STR),
        Column('pkg_appop_access', DataType.STR),
        Column('pkg_appop_type', DataType.STR),
        Column('pkg_appop_timestamp', DataType.STR),
    ],
    description="MVT Android appops output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
