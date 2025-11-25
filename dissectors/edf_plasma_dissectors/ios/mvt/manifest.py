"""MVT iOS Manifest artifact dissector"""

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
    pattern = 'manifest.json'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    manifest_detected = ctx.filepath.parent / 'manifest_detected.json'
    detected_file_ids = set()
    if manifest_detected.is_file():
        for record in read_json(manifest_detected):
            detected_file_ids.add(record['file_id'])
    records = read_json(ctx.filepath)
    if records is None:
        ctx.register_error(f"failed to load JSON data from: {ctx.filepath}")
        return
    for record in records:
        if not isinstance(record, dict):
            ctx.register_error(f"unsupported format: {ctx.filepath}")
            return
        yield {
            'btime': record['created'],
            'mtime': record['modified'],
            'mode': record['mode'],
            'owner': record['owner'],
            'size': record['size'],
            'domain': record['domain'],
            'relpath': record['relative_path'],
            'is_detected': record['file_id'] in detected_file_ids,
        }


DISSECTOR = Dissector(
    slug='ios_mvt_manifest',
    tags={Tag.MVT, Tag.IOS},
    columns=[
        Column('btime', DataType.STR),
        Column('mtime', DataType.STR),
        Column('mode', DataType.STR),
        Column('owner', DataType.STR),
        Column('size', DataType.INT),
        Column('domain', DataType.STR),
        Column('relpath', DataType.STR),
        Column('is_detected', DataType.BOOL),
    ],
    description="MVT iOS manifest output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
