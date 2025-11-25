"""APT History Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.streaming import (
    lines_from_filepath,
    lines_from_gz_filepath,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_END_TIME = 'End-Date: '
_BEG_TIME = 'Start-Date: '
_COMMANDLINE = 'Commandline: '


def _parse_kv(line: str):
    _, val = line.split(': ', 1)
    return val


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'log/apt/history.log*'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    lines_from_fp = (
        lines_from_gz_filepath
        if ctx.filepath.suffix == '.gz'
        else lines_from_filepath
    )
    record = {}
    for line in lines_from_fp(ctx.filepath):
        line = line.strip()
        if line.startswith(_BEG_TIME):
            record['hist_beg_time'] = _parse_kv(line)
            continue
        if line.startswith(_COMMANDLINE):
            record['hist_command'] = _parse_kv(line)
            continue
        if line.startswith(_END_TIME):
            record['hist_end_time'] = _parse_kv(line)
            yield record
            record = {}


DISSECTOR = Dissector(
    slug='linux_apt_history',
    tags={Tag.LINUX},
    columns=[
        Column('hist_beg_time', DataType.STR),
        Column('hist_end_time', DataType.STR),
        Column('hist_command', DataType.STR),
    ],
    description="apt history log",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
