"""Linux systemd service Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.streaming import lines_from_filepath
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    pattern = '*.timer'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    record = {}
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):
            record.update({'tmr_section': line[1:-1]})
            continue
        option, value = line.split('=', 1)
        record.update({'tmr_option': option, 'tmr_value': value})
        yield record


DISSECTOR = Dissector(
    slug='linux_systemd_timer',
    tags={Tag.LINUX},
    columns=[
        Column('tmr_section', DataType.STR),
        Column('tmr_option', DataType.STR),
        Column('tmr_value', DataType.STR),
    ],
    description="systemd timer",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
