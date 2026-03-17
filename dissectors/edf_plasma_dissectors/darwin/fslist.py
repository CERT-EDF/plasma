"""Linux Filesystem List Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.json import read_jsonl
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_PATTERN = regexp(
    r'\s+'.join(
        [
            r'(?P<inode>\d+)',  # 64202
            r'(?P<block_size>\d+)',  # 0
            r'(?P<perms>[^\s]+)',  # lrwxr-xr-x
            r'(?P<links>\d+)',  # 1
            r'(?P<owner>[^\s]+)',  # user
            r'(?P<group>[^\s]+)',  # staff
            r'(?P<size>\d+)',  # 17
            r'(?P<timestamp>[^\s]+\s+[^\s]+\s+[^\s]+)',  # Mar 14 23:04
            r'(?P<path>[^\s]+)(',  # /Users/user/Library/Containers/com.apple.CloudDocs.iCloudDriveFileProvider/Data/Library/Fonts
            r'->',  # ->
            r'(?P<target>[^\s]+))?',  # target
        ]
    )
)


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'Darwin.Collector.FileMetadata%2FCollection.json'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for obj in read_jsonl(ctx.filepath):
        line = obj['Stdout'].strip()
        match = _PATTERN.fullmatch(line)
        if not match:
            continue
        yield {
            'inode': int(match.group('inode') or -1),
            'block_size': int(match.group('block_size') or -1),
            'perms': match.group('perms'),
            'links': int(match.group('links') or -1),
            'owner': match.group('owner'),
            'group': match.group('group'),
            'size': int(match.group('size') or -1),
            'timestamp': match.group('timestamp'),
            'path': match.group('path'),
            'target': match.group('target'),
        }


DISSECTOR = Dissector(
    slug='darwin_fslist',
    tags={Tag.DARWIN},
    columns=[
        Column('inode', DataType.INT),
        Column('block_size', DataType.INT),
        Column('perms', DataType.STR),
        Column('links', DataType.INT),
        Column('owner', DataType.STR),
        Column('group', DataType.STR),
        Column('size', DataType.INT),
        Column('timestamp', DataType.STR),
        Column('path', DataType.STR),
        Column('target', DataType.STR),
    ],
    description="Velociraptor artifact Darwin.Collector.FileMetadata",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
