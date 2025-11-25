"""Windows Powershell history artifact dissector"""

from json import dumps
from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.json import read_jsonl
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'Linux.Network.Netstat.json'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for obj in read_jsonl(ctx.filepath):
        proc_info = obj['ProcessInfo']
        yield {
            'proc_uid': int(obj['uid']),
            'proc_pid': int(proc_info['Pid']),
            'proc_cmd': dumps(proc_info['CommandLine'].split('\u0000')),
            'proc_type': proc_info['Type'],
            'proc_file': proc_info['Filename'],
            'proc_inode': int(proc_info['Inode']),
            'state': obj['State'].lower(),
            'laddr': obj['LocalAddr']['IP'],
            'lport': obj['LocalAddr']['Port'],
            'raddr': obj['RemoteAddr']['IP'],
            'rport': obj['RemoteAddr']['Port'],
        }


DISSECTOR = Dissector(
    slug='linux_netstat',
    tags={Tag.LINUX},
    columns=[
        Column('proc_uid', DataType.INT),
        Column('proc_pid', DataType.INT),
        Column('proc_cmd', DataType.STR),
        Column('proc_type', DataType.STR),
        Column('proc_file', DataType.STR),
        Column('proc_inode', DataType.INT),
        Column('state', DataType.STR),
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
