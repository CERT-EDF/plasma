"""Linux Authlog Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.streaming import (
    lines_from_filepath,
    lines_from_gz_filepath,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_LOGGER = get_logger('dissectors.linux.authlog')
_OLD_PATTERN = regexp(
    r'(?P<time>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>[^\s]+)\s(?P<source>[^:]+):\s(?P<message>.*)'
)
_NEW_PATTERN = regexp(
    r'(?P<time>\d+-\d+-\d+T\d+:\d+:\d+(\.\d+)?\+\d+:?\d+)\s+(?P<host>[^\s]+)\s(?P<source>[^:]+):\s(?P<message>.*)'
)


def _select_impl(directory: Path) -> PathIterator:
    patterns = (
        'secure*',
        'auth.log*',
    )
    for pattern in patterns:
        yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    lines_from_fp = (
        lines_from_gz_filepath
        if ctx.filepath.suffix == '.gz'
        else lines_from_filepath
    )
    for line in lines_from_fp(ctx.filepath):
        line = line.rstrip()
        skipped = True
        for pattern in (_OLD_PATTERN, _NEW_PATTERN):
            match = pattern.fullmatch(line)
            if not match:
                continue
            skipped = False
            yield {
                'auth_time': match.group('time'),
                'auth_host': match.group('host'),
                'auth_source': match.group('source'),
                'auth_message': match.group('message'),
            }
            break
        if skipped:
            _LOGGER.warning("skipped line: %s", line)


DISSECTOR = Dissector(
    slug='linux_authlog',
    tags={Tag.LINUX},
    columns=[
        Column('auth_time', DataType.STR),
        Column('auth_host', DataType.STR),
        Column('auth_source', DataType.STR),
        Column('auth_message', DataType.STR),
    ],
    description="auth.log* and secure*",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
