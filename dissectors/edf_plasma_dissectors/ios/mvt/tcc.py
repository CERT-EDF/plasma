"""MVT iOS TCC artifact dissector"""

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
    pattern = 'tcc.json'
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
        yield {
            'tcc_client': record['client'],
            'tcc_client_type': record['client_type'],
            'tcc_auth_value': record['auth_value'],
            'tcc_auth_reason_desc': record['auth_reason_desc'],
            'tcc_service': record['service'],
        }


DISSECTOR = Dissector(
    slug='ios_mvt_tcc',
    tags={Tag.MVT, Tag.IOS},
    columns=[
        Column('tcc_client', DataType.STR),
        Column('tcc_client_type', DataType.STR),
        Column('tcc_auth_value', DataType.STR),
        Column('tcc_auth_reason_desc', DataType.STR),
        Column('tcc_service', DataType.STR),
    ],
    description="MVT iOS tcc output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
