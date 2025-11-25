"""MVT Android Packages artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.json import read_json
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    yield from select(directory, 'packages.json')


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    records = read_json(ctx.filepath)
    if records is None:
        ctx.register_error(f"failed to load JSON data from: {ctx.filepath}")
        return
    for record in records:
        if not isinstance(record, dict):
            ctx.register_error(f"unsupported format: {ctx.filepath}")
            return

        files = {}
        if record['files']:
            files = record['files'][0]

        yield {
            'pkg_btime': record['first_install_time'],
            'pkg_mtime': record['last_update_time'],
            'pkg_name': record['package_name'],
            'pkg_file': record['file_name'],
            'pkg_is_disabled': record['disabled'],
            'pkg_is_system': record['system'],
            'pkg_is_third_party': record['third_party'],
            'pkg_path': files.get('path'),
            'pkg_sha256': files.get('sha256'),
            'pkg_version': record['version_name'],
            'pkg_perms': record['requested_permissions'],
        }


DISSECTOR = Dissector(
    slug='android_mvt_packages',
    tags={Tag.MVT, Tag.ANDROID},
    columns=[
        Column('pkg_btime', DataType.STR),
        Column('pkg_mtime', DataType.STR),
        Column('pkg_name', DataType.STR),
        Column('pkg_file', DataType.STR),
        Column('pkg_is_disabled', DataType.BOOL),
        Column('pkg_is_system', DataType.BOOL),
        Column('pkg_is_third_party', DataType.BOOL),
        Column('pkg_path', DataType.STR),
        Column('pkg_sha256', DataType.STR),
        Column('pkg_version', DataType.STR),
        Column('pkg_perms', DataType.STR),
    ],
    description="MVT Android packages output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
