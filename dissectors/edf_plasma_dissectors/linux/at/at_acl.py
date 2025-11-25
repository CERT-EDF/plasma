"""Linux at.allow and at.deny Dissector"""

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
    patterns = (
        'etc/at.deny',
        'etc/at.allow',
    )
    for pattern in patterns:
        yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    allowed = 1 if ctx.filepath.name == 'at.allow' else 0
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        yield {
            'at_user': line,
            'at_allowed': allowed,
        }


DISSECTOR = Dissector(
    slug='linux_at_acl',
    tags={Tag.LINUX},
    columns=[
        Column('at_user', DataType.STR),
        Column('at_allowed', DataType.INT),
    ],
    description="at.allow and at.deny",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
