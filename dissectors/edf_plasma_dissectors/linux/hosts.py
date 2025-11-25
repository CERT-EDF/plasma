"""Linux hosts Dissector"""

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

_PATTERN = regexp(r'(?P<address>[^#\s]+)\s+(?P<hostnames>.*)')


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'etc/hosts'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        match = _PATTERN.fullmatch(line)
        if not match:
            continue
        hostnames = match.group('hostnames').strip().split(' ')
        for hostname in filter(None, hostnames):
            yield {
                'host_addr': match.group('address'),
                'host_name': hostname,
            }


DISSECTOR = Dissector(
    slug='linux_hosts',
    tags={Tag.LINUX},
    columns=[
        Column('host_addr', DataType.STR),
        Column('host_name', DataType.STR),
    ],
    description="hosts config",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
