"""Linux fstab Dissector"""

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
    r'(?P<filesystem>[^#\s]+)\s+(?P<mountpoint>[^\s]+)\s+(?P<type>[^\s]+)\s+(?P<options>[^\s]+)\s+(?P<dump>[^\s]+)\s+(?P<pass>[^\s]+)'
)


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'etc/fstab'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        match = _PATTERN.fullmatch(line)
        if not match:
            continue
        yield {
            'fstab_filesystem': match.group('filesystem'),
            'fstab_mountpoint': match.group('mountpoint'),
            'fstab_type': match.group('type'),
            'fstab_options': match.group('options'),
            'fstab_dump': int(match.group('dump')),
            'fstab_pass': int(match.group('pass')),
        }


DISSECTOR = Dissector(
    slug='linux_fstab',
    tags={Tag.LINUX},
    columns=[
        Column('fstab_filesystem', DataType.STR),
        Column('fstab_mountpoint', DataType.STR),
        Column('fstab_type', DataType.STR),
        Column('fstab_options', DataType.STR),
        Column('fstab_dump', DataType.INT),
        Column('fstab_pass', DataType.INT),
    ],
    description="fstab config",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
