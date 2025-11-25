"""YUM History Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import from_iso_fmt, to_iso_fmt, to_utc
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.streaming import (
    lines_from_filepath,
    lines_from_gz_filepath,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_PATTERN = regexp(
    r'(?P<time>[^\s]+)\s+DDEBUG\s+Command:\s+(?P<command>yum\s+.*)'
)


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'log/dnf.log*'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    lines_from_fp = (
        lines_from_gz_filepath
        if ctx.filepath.suffix == '.gz'
        else lines_from_filepath
    )
    for line in lines_from_fp(ctx.filepath):
        match = _PATTERN.fullmatch(line.strip())
        if not match:
            continue
        yield {
            'hist_time': to_iso_fmt(to_utc(from_iso_fmt(match.group('time')))),
            'hist_command': match.group('command'),
        }


DISSECTOR = Dissector(
    slug='linux_yum_history',
    tags={Tag.LINUX},
    columns=[
        Column('hist_time', DataType.STR),
        Column('hist_command', DataType.STR),
    ],
    description="yum history log",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
