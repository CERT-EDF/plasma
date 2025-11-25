"""Linux passwd Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.streaming import lines_from_filepath
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_PATTERN = regexp(
    r'(?P<name>[^:]*):(?P<digest>[^:]*):(?P<uid>[^:]*):(?P<gid>[^:]*):(?P<comment>[^:]*):(?P<home>[^:]*):(?P<shell>[^:]*)'
)


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'etc/passwd'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        match = _PATTERN.fullmatch(line)
        if not match:
            continue
        yield {
            'user_name': match.group('name'),
            'user_digest': match.group('digest'),
            'user_uid': int(match.group('uid') or -1),
            'user_gid': int(match.group('gid') or -1),
            'user_comment': match.group('comment'),
            'user_home': match.group('home'),
            'user_shell': match.group('shell'),
        }


DISSECTOR = Dissector(
    slug='linux_passwd',
    tags={Tag.LINUX},
    columns=[
        Column('user_name', DataType.STR),
        Column('user_digest', DataType.STR),
        Column('user_uid', DataType.INT),
        Column('user_gid', DataType.INT),
        Column('user_comment', DataType.STR),
        Column('user_home', DataType.STR),
        Column('user_shell', DataType.STR),
    ],
    description="passwd config",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
