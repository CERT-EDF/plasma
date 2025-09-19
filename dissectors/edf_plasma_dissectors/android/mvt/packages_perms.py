"""MVT Android Packages Perms artifact dissector"""

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
    for filepath in directory.rglob('packages.json'):
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
            yield {
                'pkg_name': record.get('package_name'),
                'pkg_perm_name': perm.get('name'),
                'pkg_perm_granted': perm.get('granted'),
                'pkg_perm_type': perm.get('type'),
            }


DISSECTOR = Dissector(
    slug='android_mvt_packages_perms',
    tags={Tag.MVT, Tag.ANDROID},
    columns=[
        Column('pkg_name', DataType.STR),
        Column('pkg_perm_name', DataType.STR),
        Column('pkg_perm_granted', DataType.BOOL),
        Column('pkg_perm_type', DataType.STR),
    ],
    description="MVT Android packages permissions output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
