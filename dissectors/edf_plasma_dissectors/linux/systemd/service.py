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
    pattern = '*.service'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    record = {}
    multiline = False
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):
            record.update({'svc_section': line[1:-1]})
            continue
        if multiline:
            value = value.rstrip('\\') + line
        else:
            option, value = line.split('=', 1)
        multiline = value.endswith('\\')
        if not multiline:
            record.update({'svc_option': option, 'svc_value': value})
            yield record


DISSECTOR = Dissector(
    slug='linux_systemd_service',
    tags={Tag.LINUX},
    columns=[
        Column('svc_section', DataType.STR),
        Column('svc_option', DataType.STR),
        Column('svc_value', DataType.STR),
    ],
    description="systemd service",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
