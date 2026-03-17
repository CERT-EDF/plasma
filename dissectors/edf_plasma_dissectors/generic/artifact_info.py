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
from edf_plasma_core.helper.json import read_jsonl
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_MAGIKA = instanciate_magika()


def _select_impl(directory: Path) -> PathIterator:
    yield from select(directory, '*')


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    ident_result = identify_filepath(ctx.filepath, magika=_MAGIKA)
    record = {
        'size': '',
        'created': '',
        'changed': '',
        'accessed': '',
        'modified': '',
        'magic_mime': ident_result.magic_mime,
        'magic_info': ident_result.magic_info,
        'magika_mime': ident_result.magika_mime,
        'magika_info': ident_result.magika_info,
        'magika_label': ident_result.magika_label,
    }
    parts = str(ctx.filepath).split('uploads/file')
    if len(parts) == 2:
        record.update(ctx.state.get(parts[-1], {}))
    yield record


def _set_state_impl(target: Path) -> dict:
    if not target.is_dir():
        return {}
    pattern = 'results/*.Collector.FileContent%2FCollection.json'
    try:
        selected = next(select(target, pattern))
    except StopIteration:
        return {}
    state = {}
    for obj in read_jsonl(selected):
        state[obj['SourceFile']] = {
            'size': obj['Size'],
            'created': obj['Created'],
            'changed': obj['Changed'],
            'accessed': obj['LastAccessed'],
            'modified': obj['Modified'],
        }
    return state


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
        Column('size', DataType.STR),
        Column('created', DataType.STR),
        Column('changed', DataType.STR),
        Column('accessed', DataType.STR),
        Column('modified', DataType.STR),
        Column('magic_mime', DataType.STR),
        Column('magic_info', DataType.STR),
        Column('magika_mime', DataType.STR),
        Column('magika_info', DataType.STR),
        Column('magika_label', DataType.STR),
    ],
    description="Generic artifact information",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
    set_state_impl=_set_state_impl,
)
register_dissector(DISSECTOR)
