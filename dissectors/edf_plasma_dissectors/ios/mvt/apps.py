"""MVT iOS Apps artifact dissector"""

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
    for filepath in directory.rglob('applications.json'):
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
        record_dl_info = record.get('com.apple.iTunesStore.downloadInfo', {})
        yield {
            'app_name': record.get('name', ''),
            'app_source': record.get('sourceApp', 'com.apple.AppStore'),
            'app_author': record.get('artistName', ''),
            'app_version': record.get('bundleVersion', ''),
            'app_release_date': record.get('releaseDate', ''),
            'app_purchased_date': record_dl_info.get('purchaseDate', ''),
        }


DISSECTOR = Dissector(
    slug='ios_mvt_apps',
    tags={Tag.MVT, Tag.IOS},
    columns=[
        Column('app_name', DataType.STR),
        Column('app_source', DataType.STR),
        Column('app_author', DataType.STR),
        Column('app_version', DataType.STR),
        Column('app_release_date', DataType.STR),
        Column('app_purchased_date', DataType.STR),
    ],
    description="MVT iOS apps output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
