"""MVT iOS DataUsage artifact dissector"""

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
    pattern = 'datausage.json'
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
        wwan_in = record['wwan_in'] or -1
        wwan_out = record['wwan_out'] or -1
        yield {
            'du_first_time': record['first_isodate'],
            'du_time': record['isodate'],
            'du_proc_name': record['proc_name'],
            'du_wwan_in': int(wwan_in),
            'du_wwan_out': int(wwan_out),
        }


DISSECTOR = Dissector(
    slug='ios_mvt_datausage',
    tags={Tag.MVT, Tag.IOS},
    columns=[
        Column('du_first_time', DataType.STR),
        Column('du_time', DataType.STR),
        Column('du_proc_name', DataType.STR),
        Column('du_wwan_in', DataType.INT),
        Column('du_wwan_out', DataType.INT),
    ],
    description="MVT iOS datausage output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
