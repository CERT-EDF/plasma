"""Darwin Version Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

from .helper import load_plist


_GLOB_PATTERN = 'SystemVersion.plist'


def _select_impl(directory: Path) -> PathIterator:
    yield from select(directory, _GLOB_PATTERN)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    data = load_plist(ctx.filepath)
    for field, value in data.items():
        yield {'field': field, 'value': value}


DISSECTOR = Dissector(
    slug='darwin_version',
    tags={Tag.DARWIN},
    columns=[
        Column('field', DataType.STR),
        Column('value', DataType.STR),
    ],
    description="Darwin system version",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
