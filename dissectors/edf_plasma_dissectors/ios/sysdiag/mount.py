"""Sysdiagnose mount artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_PATTERN = regexp(
    r'(?P<mnt_dev>.*) on (?P<mnt_path>.*) \((?P<mnt_opts>[^\)]+)\)'
)


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob('mount.txt'):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open(encoding='utf-8') as fobj:
        for line in fobj:
            line = line.strip()
            if not line:
                continue
            match = _PATTERN.fullmatch(line)
            if not match:
                continue
            yield {
                'mnt_dev': match.group('mnt_dev'),
                'mnt_path': match.group('mnt_path'),
                'mnt_opts': match.group('mnt_opts'),
            }


DISSECTOR = Dissector(
    slug='ios_sysdiag_mount',
    tags={Tag.SYSDIAG, Tag.IOS},
    columns=[
        Column('mnt_dev', DataType.STR),
        Column('mnt_path', DataType.STR),
        Column('mnt_opts', DataType.STR),
    ],
    description="iOS sysdiagnose mount output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
