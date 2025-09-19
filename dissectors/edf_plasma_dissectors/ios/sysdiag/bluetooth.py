"""Sysdiagnose bluetooth artifact dissector"""

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
    for filepath in directory.rglob('WiFi/bluetooth_status.txt'):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open(encoding='utf-8') as fobj:
        groups = [[]]
        for line in fobj:
            line = line.strip()
            if not line and groups[-1]:
                groups.append([])
                continue
            if not line:
                continue
            groups[-1].append(line)
        for k in range(2, len(groups)):
            group = groups[k]
            if not group:
                continue
            yield {
                'bt_dev_name': group[0],
                'bt_dev_addr': group[1].split(':', 1)[-1].strip(),
                'bt_dev_paired': group[2].split(':', 1)[-1].strip() == 'Yes',
                'bt_dev_cloud_paired': group[3].split(':', 1)[-1].strip()
                == 'Yes',
            }


DISSECTOR = Dissector(
    slug='ios_sysdiag_bluetooth',
    tags={Tag.SYSDIAG, Tag.IOS},
    columns=[
        Column('bt_dev_name', DataType.STR),
        Column('bt_dev_addr', DataType.STR),
        Column('bt_dev_paired', DataType.BOOL),
        Column('bt_dev_cloud_paired', DataType.BOOL),
    ],
    description="iOS sysdiagnose bluetooth status output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
