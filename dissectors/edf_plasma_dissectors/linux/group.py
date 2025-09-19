"""Linux group Dissector"""

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

_GLOB_PATTERN = 'etc/group'
_PATTERN = regexp(
    r'(?P<name>[^:]*):(?P<digest>[^:]*):(?P<gid>[^:]*):(?P<groups>[^:]*)'
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
            'group_name': match.group('name'),
            'group_digest': match.group('digest'),
            'group_gid': int(match.group('gid') or -1),
            'group_groups': match.group('groups'),
        }


DISSECTOR = Dissector(
    slug='linux_group',
    tags={Tag.LINUX},
    columns=[
        Column('group_name', DataType.STR),
        Column('group_digest', DataType.STR),
        Column('group_gid', DataType.INT),
        Column('group_groups', DataType.STR),
    ],
    description="group config",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
