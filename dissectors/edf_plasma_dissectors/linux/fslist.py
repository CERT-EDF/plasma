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
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_GLOB_PATTERN = 'Linux.Collector.FileMetadata%2FCollection.json'
_PATTERN = regexp(
    r'\s+'.join(
        [
            r'(?P<inode>\d+)',  # 26607617
            r'(?P<block_size>\d+)',  # 4
            r'(?P<perms>[^\s]+)',  # drwxr-xr-x
            r'(?P<links>\d+)',  # 2
            r'(?P<owner>[^\s]+)',  # root
            r'(?P<group>[^\s]+)',  # root
            r'(?P<size>\d+)',  # 4096
            r'(?P<timestamp>[^\s]+\s+[^\s]+\s+[^\s]+)',  # août  9  2022
            r'(?P<path>[^\s]+)(',  # /mnt
            r'->',  # ->
            r'(?P<target>[^\s]+))?',  # target
        ]
    )
)


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob(_GLOB_PATTERN):
        if not filepath.is_file():
            continue
        yield filepath


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
    slug='linux_fslist',
    tags={Tag.LINUX},
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
    description="Velociraptor artifact Linux.Collector.FileMetadata",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
