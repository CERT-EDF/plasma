"""Darwin Install History Dissector"""

from json import dumps
from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import to_iso_fmt, with_utc
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

from .helper import load_plist

_GLOB_PATTERN = 'Receipts/InstallHistory.plist'


def _select_impl(directory: Path) -> PathIterator:
    yield from select(directory, _GLOB_PATTERN)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    data = load_plist(ctx.filepath)
    for item in data:
        yield {
            'datetime': to_iso_fmt(with_utc(item['date'])),
            'name': item['displayName'],
            'version': item['displayVersion'],
            'process': item['processName'],
            'packages': dumps(item.get('packageIdentifiers', [])),
        }


DISSECTOR = Dissector(
    slug='darwin_install_history',
    tags={Tag.DARWIN},
    columns=[
        Column('datetime', DataType.STR),
        Column('name', DataType.STR),
        Column('version', DataType.STR),
        Column('process', DataType.STR),
        Column('packages', DataType.STR),
    ],
    description="Software install history",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
