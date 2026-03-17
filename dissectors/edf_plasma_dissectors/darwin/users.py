"""Darwin Users Dissector"""

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


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'var/db/dslocal/nodes/Default/users/*.plist'
    yield from select(directory, pattern)


def _get_value(data: dict, field: str) -> str:
    return ','.join(data[field])


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    data = load_plist(ctx.filepath)
    yield {
        'uid': _get_value(data, 'uid'),
        'gid': _get_value(data, 'gid'),
        'name': _get_value(data, 'name'),
        'home': _get_value(data, 'home'),
        'shell': _get_value(data, 'shell'),
        'passwd': _get_value(data, 'passwd'),
        'realname': _get_value(data, 'realname'),
        'generateduid': _get_value(data, 'generateduid'),
    }


DISSECTOR = Dissector(
    slug='darwin_users',
    tags={Tag.DARWIN},
    columns=[
        Column('uid', DataType.INT),
        Column('gid', DataType.INT),
        Column('name', DataType.STR),
        Column('home', DataType.STR),
        Column('shell', DataType.STR),
        Column('passwd', DataType.STR),
        Column('realname', DataType.STR),
        Column('generateduid', DataType.STR),
    ],
    description="System version information",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
