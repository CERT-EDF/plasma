"""Sysdiagnose shutdown artifact dissector"""

from collections import Counter
from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import datetime, to_iso_fmt, with_utc
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_SIGTERM_PATTERN = regexp(r'SIGTERM: \[(?P<timestamp>\d+)\].*')
_REMAINING_PATTERN = regexp(
    r'remaining client pid: (?P<pid>\d+) \((?P<path>[^\)]+)\)'
)


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'Extra/shutdown.log'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open(encoding='utf-8') as fobj:
        record = {}
        counter = Counter()
        for line in fobj:
            line = line.strip()
            match = _REMAINING_PATTERN.fullmatch(line)
            if match:
                counter.update(
                    ((int(match.group('pid')), match.group('path')),)
                )
            match = _SIGTERM_PATTERN.fullmatch(line)
            if match:
                record['term_time'] = to_iso_fmt(
                    with_utc(
                        datetime.fromtimestamp(int(match.group('timestamp')))
                    )
                )
                for tup, count in counter.most_common(len(counter)):
                    pid, path = tup
                    record['term_app_pid'] = pid
                    record['term_app_path'] = path
                    record['term_app_count'] = count
                    yield record
                record = {}
                counter = Counter()


DISSECTOR = Dissector(
    slug='ios_sysdiag_shutdown',
    tags={Tag.SYSDIAG, Tag.IOS},
    columns=[
        Column('term_time', DataType.STR),
        Column('term_app_pid', DataType.INT),
        Column('term_app_path', DataType.STR),
        Column('term_app_count', DataType.INT),
    ],
    description="iOS sysdiagnose shutdown output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
