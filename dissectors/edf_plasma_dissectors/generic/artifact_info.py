"""Artifact info dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.identifying import (
    identify_filepath,
    instanciate_magika,
)
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_MAGIKA = instanciate_magika()


def _select_impl(directory: Path) -> PathIterator:
    yield from select(directory, '*')


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    ident_result = identify_filepath(ctx.filepath, magika=_MAGIKA)
    yield {
        'magic_mime': ident_result.magic_mime,
        'magic_info': ident_result.magic_info,
        'magika_mime': ident_result.magika_mime,
        'magika_info': ident_result.magika_info,
        'magika_label': ident_result.magika_label,
    }


DISSECTOR = Dissector(
    slug='generic_artifact_info',
    tags={
        Tag.GENERIC,
        Tag.WINDOWS,
        Tag.LINUX,
        Tag.ANDROID,
        Tag.DARWIN,
        Tag.IOS,
    },
    columns=[
        Column('magic_mime', DataType.STR),
        Column('magic_info', DataType.STR),
        Column('magika_mime', DataType.STR),
        Column('magika_info', DataType.STR),
        Column('magika_label', DataType.STR),
    ],
    description="Generic artifact information",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
