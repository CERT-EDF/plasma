"""Windows IIS journal artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_LINE_PATTERN = regexp(
    r'(?P<date>[^\s]+)\s+(?P<time>[^\s]+)\s+(?P<category>[^\s]+)\s+(?P<message>.*)\s+\[CLIENT: (?P<client>[^\]]+)\]'
)


def _select_impl(directory: Path) -> PathIterator:
    pattern = ci_glob_pattern('ERRORLOG*')
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open('r', encoding='utf-16') as fobj:
        # parse header
        for line in fobj:
            line = line.rstrip()
            match = _LINE_PATTERN.fullmatch(line)
            if not match:
                continue
            date = match.group('date')
            time = match.group('time')
            yield {
                'time': f'{date}T{time}0Z',
                'category': match.group('category'),
                'client': match.group('client'),
                'message': match.group('message'),
            }


DISSECTOR = Dissector(
    slug='windows_mssql',
    tags={Tag.WINDOWS},
    columns=[
        Column('time', DataType.STR),
        Column('category', DataType.STR),
        Column('client', DataType.STR),
        Column('message', DataType.STR),
    ],
    description="MSSQL ERRORLOG entries",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
