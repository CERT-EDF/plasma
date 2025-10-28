"""Windows Powershell history artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.json import read_jsonl
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob('Windows.Network.Netstat.json'):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for obj in read_jsonl(ctx.filepath):
        yield {
            'time': obj['Timestamp'],
            'pid': obj['Pid'],
            'name': obj['Name'],
            'family': obj['Family'].lower(),
            'type': obj['Type'].lower(),
            'status': obj['Status'].lower(),
            'laddr': obj['Laddr.IP'],
            'lport': obj['Laddr.Port'],
            'raddr': obj['Raddr.IP'],
            'rport': obj['Raddr.Port'],
        }


DISSECTOR = Dissector(
    slug='windows_netstat',
    tags={Tag.WINDOWS},
    columns=[
        Column('time', DataType.STR),
        Column('pid', DataType.INT),
        Column('name', DataType.STR),
        Column('family', DataType.STR),
        Column('type', DataType.STR),
        Column('status', DataType.STR),
        Column('laddr', DataType.STR),
        Column('lport', DataType.INT),
        Column('raddr', DataType.STR),
        Column('rport', DataType.INT),
    ],
    description="Network connections",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
