"""Linux logrotate Dissector"""

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

_GLOB_PATTERN = 'resolv.conf'


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob(_GLOB_PATTERN):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip().replace('\t', ' ')
        if line.startswith('nameserver'):
            _, ns_addr = line.split(' ', 1)
            yield {'ns_addr': ns_addr.strip()}


DISSECTOR = Dissector(
    slug='linux_resolv',
    tags={Tag.LINUX},
    columns=[
        Column('ns_addr', DataType.STR),
    ],
    description="resolv.conf config",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
