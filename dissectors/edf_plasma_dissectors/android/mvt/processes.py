"""MVT Android Processes artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.json import read_json
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob('processes.json'):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    records = read_json(ctx.filepath)
    if records is None:
        ctx.register_error(f"failed to load JSON data from: {ctx.filepath}")
        return
    for record in records:
        if not isinstance(record, dict):
            ctx.register_error(f"unsupported format: {ctx.filepath}")
            return
        yield {
            'proc_name': record['proc_name'],
            'proc_user': record['user'],
            'proc_pid': record['pid'],
            'proc_ppid': record['ppid'],
            'proc_vmem_size': record['virtual_memory_size'],
            'proc_rset_size': record['resident_set_size'],
        }


DISSECTOR = Dissector(
    slug='android_mvt_processes',
    tags={Tag.MVT, Tag.ANDROID},
    columns=[
        Column('proc_name', DataType.STR),
        Column('proc_user', DataType.STR),
        Column('proc_pid', DataType.INT),
        Column('proc_ppid', DataType.INT),
        Column('proc_vmem_size', DataType.INT),
        Column('proc_rset_size', DataType.INT),
    ],
    description="MVT Android processes output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
