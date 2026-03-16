"""Darwin Install Log Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.streaming import lines_from_filepath
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


_GLOB_PATTERN = 'var/log/system.log'
_RECORD_PATTERN = regexp(
    r'(?P<date>(\d{4}(-\d\d){2}|[A-Z][a-z]+\s+\d{1,2})) (?P<time>[^+\-]+)(?P<offset>[^ ]+) (?P<host>[^ ]+) (?P<process>[^\[]+)\[(?P<pid>\d+)\]: (?P<message>.*)'
)


def _select_impl(directory: Path) -> PathIterator:
    yield from select(directory, _GLOB_PATTERN)


def _build_record(match, message: str) -> dict:
    return {
        'date': match.group('date'),
        'time': match.group('time'),
        'offset': match.group('offset'),
        'host': match.group('host'),
        'process': match.group('process'),
        'pid': match.group('pid'),
        'message': message,
    }


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    prev_match = None
    prev_message = ''
    for line in lines_from_filepath(ctx.filepath):
        match = _RECORD_PATTERN.match(line)
        if not match:
            prev_message += line
            continue
        if prev_match:
            yield _build_record(prev_match, prev_message)
        prev_match = match
        prev_message = match.group('message')
    if prev_match:
        yield _build_record(prev_match, prev_message)



DISSECTOR = Dissector(
    slug='darwin_system_log',
    tags={Tag.DARWIN},
    columns=[
        Column('date', DataType.STR),
        Column('time', DataType.STR),
        Column('offset', DataType.STR),
        Column('host', DataType.STR),
        Column('process', DataType.STR),
        Column('pid', DataType.INT),
        Column('message', DataType.STR),
    ],
    description="System log",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
