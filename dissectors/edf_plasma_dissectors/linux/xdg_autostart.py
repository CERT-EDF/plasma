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
    pattern = 'xdg/autostart/*'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    record = {}
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):
            continue
        option, value = line.split('=', 1)
        record.update({'xdg_option': option, 'xdg_value': value})
        yield record


DISSECTOR = Dissector(
    slug='linux_xdg_autostart',
    tags={Tag.LINUX},
    columns=[
        Column('xdg_option', DataType.STR),
        Column('xdg_value', DataType.STR),
    ],
    description="Linux xdg autostart",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
