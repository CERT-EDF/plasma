"""Sysdiagnose disk artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob('disks.txt'):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open(encoding='utf-8') as fobj:
        for line in fobj:
            line = line.strip()
            if not line:
                continue
            if line.startswith('Filesystem'):
                continue
            dev, size, used, avail, _, _, _, _, mnt = line.split()
            yield {
                'disk_dev': dev,
                'disk_size': size,
                'disk_used': used,
                'disk_avail': avail,
                'disk_mnt': mnt,
            }


DISSECTOR = Dissector(
    slug='ios_sysdiag_disk',
    tags={Tag.SYSDIAG, Tag.IOS},
    columns=[
        Column('disk_dev', DataType.STR),
        Column('disk_size', DataType.STR),
        Column('disk_used', DataType.STR),
        Column('disk_avail', DataType.STR),
        Column('disk_mnt', DataType.STR),
    ],
    description="iOS sysdiagnose disk output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
