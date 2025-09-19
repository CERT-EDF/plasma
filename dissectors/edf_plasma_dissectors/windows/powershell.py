"""Windows Powershell history artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_PATTERN = ci_glob_pattern('ConsoleHost_history.txt')


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob(_PATTERN):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open('r') as fobj:
        for command in fobj:
            command = command.rstrip()
            yield {
                'ps_command': command,
            }


DISSECTOR = Dissector(
    slug='windows_powershell',
    tags={Tag.WINDOWS},
    columns=[
        Column('ps_command', DataType.STR),
    ],
    description="Powershell command line history",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
