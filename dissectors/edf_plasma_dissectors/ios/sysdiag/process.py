"""Sysdiagnose ps artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'ps.txt'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open(encoding='utf-8') as fobj:
        try:
            next(fobj)  # skip header
        except StopIteration:
            return
        for line in fobj:
            line = line.strip().split()
            if not line:
                continue
            yield {
                'ps_user': line[0],
                'ps_uid': line[1],
                'ps_pid': line[3],
                'ps_ppid': line[4],
                'ps_started': line[15],
                'ps_command': ' '.join(line[17:]),
            }


DISSECTOR = Dissector(
    slug='ios_sysdiag_ps',
    tags={Tag.SYSDIAG, Tag.IOS},
    columns=[
        Column('ps_user', DataType.STR),
        Column('ps_uid', DataType.INT),
        Column('ps_pid', DataType.INT),
        Column('ps_ppid', DataType.INT),
        Column('ps_started', DataType.STR),
        Column('ps_command', DataType.STR),
    ],
    description="iOS sysdiagnose ps output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
