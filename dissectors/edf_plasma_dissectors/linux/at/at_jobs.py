"""Linux at jobs Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import from_unix_timestamp, to_iso_fmt
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'atjobs/a*'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    at_job_id = int(ctx.filepath.name[1:6], 16)
    at_job_time = int(ctx.filepath.name[6:], 16) * 60 * 1000 * 1000
    at_job_time = to_iso_fmt(from_unix_timestamp(at_job_time))
    yield {
        'at_job_id': at_job_id,
        'at_job_time': at_job_time,
    }


DISSECTOR = Dissector(
    slug='linux_at_jobs',
    tags={Tag.LINUX},
    columns=[
        Column('at_job_id', DataType.INT),
        Column('at_job_time', DataType.STR),
    ],
    description="at jobs",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
