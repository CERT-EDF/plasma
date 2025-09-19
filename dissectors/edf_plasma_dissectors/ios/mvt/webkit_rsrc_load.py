"""MVT iOS WebKit Rsrc Load artifact dissector"""

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
    for filepath in directory.rglob('webkit_resource_load_statistics.json'):
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
            print(record)
            ctx.register_error(f"unsupported format: {ctx.filepath}")
            return
        yield {
            'rload_scope': record['domain'],
            'rload_fqdn': record['registrable_domain'],
            'rload_time': record['last_seen_isodate'],
            'rload_user_interact': record['had_user_interaction'],
        }


DISSECTOR = Dissector(
    slug='ios_mvt_webkit_rsrc_load',
    tags={Tag.MVT, Tag.IOS},
    columns=[
        Column('rload_scope', DataType.STR),
        Column('rload_fqdn', DataType.STR),
        Column('rload_time', DataType.STR),
        Column('rload_user_interact', DataType.STR),
    ],
    description="MVT iOS webkit resource load output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
