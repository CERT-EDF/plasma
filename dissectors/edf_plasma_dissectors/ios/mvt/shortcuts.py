"""MVT iOS Shortcuts artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.filtering import unique
from edf_plasma_core.helper.json import read_json
from edf_plasma_core.helper.matching import iter_url_fqdn
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'shortcuts.json'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    records = read_json(ctx.filepath)
    if records is None:
        ctx.register_error(f"failed to load JSON data from: {ctx.filepath}")
        return
    for record in records:
        if not isinstance(record, dict):
            ctx.register_error(f"unsupported format: {ctx.filepath}")
            return
        for action_fqdn in unique(
            url_fqdn
            for action_url in record['action_urls']
            for url_fqdn in iter_url_fqdn(action_url)
        ):
            yield {
                'scut_id': record['shortcut_id'],
                'scut_name': record['shortcut_name'],
                'scut_btime': record['isodate'],
                'scut_mtime': record['modified_date'],
                'scut_action_fqdn': action_fqdn,
            }


DISSECTOR = Dissector(
    slug='ios_mvt_shortcuts',
    tags={Tag.MVT, Tag.IOS},
    columns=[
        Column('scut_id', DataType.STR),
        Column('scut_name', DataType.STR),
        Column('scut_btime', DataType.STR),
        Column('scut_mtime', DataType.STR),
        Column('scut_action_fqdn', DataType.STR),
    ],
    description="MVT iOS shortcuts output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
