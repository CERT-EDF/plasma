"""Linux crontab Dissector"""

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

_ETC_PATTERN = regexp(
    r'(?P<min>[^#\s]+)\s+(?P<hour>[^\s]+)\s+(?P<mday>[^\s]+)\s+(?P<month>[^\s]+)\s+(?P<wday>[^\s]+)\s+(?P<username>[^\s]+)\s+(?P<command>.*)'
)
_VAR_PATTERN = regexp(
    r'(?P<min>[^#\s]+)\s+(?P<hour>[^\s]+)\s+(?P<mday>[^\s]+)\s+(?P<month>[^\s]+)\s+(?P<wday>[^\s]+)\s+(?P<command>.*)'
)


def _select_impl(directory: Path) -> PathIterator:
    patterns = (
        'etc/crontab',
        'etc/cron.d/*',
        'var/spool/cron/crontabs/*',
    )
    for pattern in patterns:
        yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    pattern = _ETC_PATTERN if 'etc' in ctx.filepath.parts else _VAR_PATTERN
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        match = pattern.fullmatch(line)
        if not match:
            continue
        try:
            username = match.group('username')
        except IndexError:
            username = ctx.filepath.name
        yield {
            'cron_min': match.group('min'),
            'cron_hour': match.group('hour'),
            'cron_mday': match.group('mday'),
            'cron_month': match.group('month'),
            'cron_wday': match.group('wday'),
            'cron_username': username,
            'cron_command': match.group('command'),
        }


DISSECTOR = Dissector(
    slug='linux_crontab',
    tags={Tag.LINUX},
    columns=[
        Column('cron_min', DataType.STR),
        Column('cron_hour', DataType.STR),
        Column('cron_mday', DataType.STR),
        Column('cron_month', DataType.STR),
        Column('cron_wday', DataType.STR),
        Column('cron_username', DataType.STR),
        Column('cron_command', DataType.STR),
    ],
    description="Crontabs",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
