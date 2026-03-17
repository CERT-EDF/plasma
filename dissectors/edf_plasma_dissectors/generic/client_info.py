"""Client info dissector"""

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
    pattern = 'client_info.json'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    data = read_json(ctx.filepath)
    for field, value in data.items():
        yield {'field': field, 'value': value}


DISSECTOR = Dissector(
    slug='generic_client_info',
    tags={
        Tag.GENERIC,
        Tag.WINDOWS,
        Tag.LINUX,
        Tag.ANDROID,
        Tag.DARWIN,
        Tag.IOS,
    },
    columns=[
        Column('field', DataType.STR),
        Column('value', DataType.STR),
    ],
    description="Generic client information",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
