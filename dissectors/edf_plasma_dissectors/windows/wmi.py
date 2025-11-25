"""Windows Powershell history artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.json import dumps, read_jsonl
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'Windows.Persistence.PermanentWMIEvents.json'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for obj in read_jsonl(ctx.filepath):
        yield {
            'filter': dumps(obj['FilterDetails']),
            'consumer': dumps(obj['ConsumerDetails']),
            'namespace': obj['Namespace'],
        }


DISSECTOR = Dissector(
    slug='windows_wmi',
    tags={Tag.WINDOWS},
    columns=[
        Column('filter', DataType.STR),
        Column('consumer', DataType.STR),
        Column('namespace', DataType.STR),
    ],
    description="WMI event filter/consumer bindings",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
