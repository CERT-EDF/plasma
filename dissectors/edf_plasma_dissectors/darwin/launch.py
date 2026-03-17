"""Darwin Launch Configuration Dissector"""

from json import dumps
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

from .helper import load_plist


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'Library/Launch*/*.plist'
    yield from select(directory, pattern)


def _extract_argv(data: dict) -> list[str] | None:
    argv = data.get('ProgramArguments')
    if argv:
        return argv
    argv = data.get('Program')
    if argv:
        return [argv]
    return None


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    data = load_plist(ctx.filepath)
    argv = _extract_argv(data)
    if not argv:
        ctx.register_error(f"argv not found in: {ctx.filepath}")
        return
    label = data.get('Label')
    if not label:
        ctx.register_error(f"label not found in: {ctx.filepath}")
        return
    yield {
        'category': ctx.filepath.parent.name,
        'label': label,
        'argv': dumps(argv),
    }


DISSECTOR = Dissector(
    slug='darwin_launch',
    tags={Tag.DARWIN},
    columns=[
        Column('category', DataType.STR),
        Column('label', DataType.STR),
        Column('argv', DataType.STR),
    ],
    description="Launch agents and daemons label and argument vectors",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
