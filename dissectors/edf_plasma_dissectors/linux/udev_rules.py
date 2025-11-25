"""Linux udev rules Dissector"""

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
    pattern = 'udev/rules.d/*.rules'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        match_keys = []
        assignment_keys = []
        for part in line.split(', '):
            keys = match_keys if '==' in part else assignment_keys
            keys.append(part)
        yield {
            'rule_match': ', '.join(match_keys),
            'rule_assign': ', '.join(assignment_keys),
        }


DISSECTOR = Dissector(
    slug='linux_udev_rules',
    tags={Tag.LINUX},
    columns=[
        Column('rule_match', DataType.STR),
        Column('rule_assign', DataType.STR),
    ],
    description="udev rules",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
