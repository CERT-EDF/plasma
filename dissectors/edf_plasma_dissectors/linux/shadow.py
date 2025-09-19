"""Linux shadow Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.streaming import lines_from_filepath
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_GLOB_PATTERN = 'etc/shadow'
_PATTERN = regexp(
    r'(?P<name>[^:]*):(?P<digest>[^:]*):(?P<lastchanged>[^:]*):(?P<min>[^:]*):(?P<max>[^:]*):(?P<warn>[^:]*):(?P<inactive>[^:]*):(?P<expire>[^:]*):'
)


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob(_GLOB_PATTERN):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        match = _PATTERN.fullmatch(line)
        if not match:
            continue
        yield {
            'user_name': match.group('name'),
            'user_digest': match.group('digest'),
            'user_lastchanged': int(match.group('lastchanged') or -1),
            'user_min': int(match.group('min') or -1),
            'user_max': int(match.group('max') or -1),
            'user_warn': int(match.group('warn') or -1),
            'user_inactive': int(match.group('inactive') or -1),
            'user_expire': int(match.group('expire') or -1),
        }


DISSECTOR = Dissector(
    slug='linux_shadow',
    tags={Tag.LINUX},
    columns=[
        Column('user_name', DataType.STR),
        Column('user_digest', DataType.STR),
        Column('user_lastchanged', DataType.INT),
        Column('user_min', DataType.INT),
        Column('user_max', DataType.INT),
        Column('user_warn', DataType.INT),
        Column('user_inactive', DataType.INT),
        Column('user_expire', DataType.INT),
    ],
    description="shadow config",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
