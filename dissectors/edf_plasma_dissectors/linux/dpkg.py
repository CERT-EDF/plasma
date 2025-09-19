"""Linux dpkg Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.streaming import lines_from_filepath
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_GLOB_PATTERN = 'dpkg/status'


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob('dpkg/status'):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    record = {}
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        if line.startswith('Package: '):
            _, package = line.split(': ', 1)
            record.update({'package': package})
        if line.startswith('Status: '):
            _, status = line.split(': ', 1)
            record.update({'status': status})
            yield record


DISSECTOR = Dissector(
    slug='linux_dpkg',
    tags={Tag.LINUX},
    columns=[
        Column('package', DataType.STR),
        Column('status', DataType.STR),
    ],
    description="dpkg status",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
