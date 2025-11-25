"""Auditd Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import from_unix_timestamp, to_iso_fmt
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.streaming import (
    lines_from_filepath,
    lines_from_gz_filepath,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_LOGGER = get_logger('dissectors.linux.auditd')
_PATTERN = regexp(
    r'type=(?P<type>[^\s]+) [^\(]+\((?P<date>[^\:]+):(?P<id>[^\)]+)\): (?P<data>.+)'
)


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'audit.log*'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    skipped = 0
    lines_from_filepath_strategy = (
        lines_from_gz_filepath
        if ctx.filepath.suffix == '.gz'
        else lines_from_filepath
    )
    for line in lines_from_filepath_strategy(ctx.filepath):
        line = line.rstrip()
        match = _PATTERN.search(line)
        if not match:
            skipped += 1
            continue
        auditd_date = float(match.group('date'))
        auditd_date = from_unix_timestamp(auditd_date * 1000 * 1000)
        yield {
            'auditd_type': match.group('type'),
            'auditd_date': to_iso_fmt(auditd_date),
            'auditd_id': match.group('id'),
            'auditd_data': match.group('data'),
        }
    if skipped:
        _LOGGER.warning("skipped %s lines.", skipped)


DISSECTOR = Dissector(
    slug='linux_auditd',
    tags={Tag.LINUX},
    columns=[
        Column('auditd_type', DataType.STR),
        Column('auditd_date', DataType.STR),
        Column('auditd_id', DataType.INT),
        Column('auditd_data', DataType.STR),
    ],
    description="auditd log",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
