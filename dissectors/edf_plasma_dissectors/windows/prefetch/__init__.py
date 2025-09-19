"""Windows prefetch artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import REF_WIN32, to_iso_fmt, with_utc
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

from .helper import (
    check_file_signature,
    get_pf_exec_filename,
    get_pf_filenames,
    get_pf_hash,
    get_pf_last_run_times,
    get_pf_run_count,
    open_file_object,
)

_LOGGER = get_logger('dissectors.microsoft.prefetch')
_PATTERN = ci_glob_pattern('*.pf')


def _parse_prefetch(ctx: DissectionContext):
    with ctx.filepath.open('rb') as fobj:
        prefetch = open_file_object(ctx, fobj)
        if prefetch is None:
            return
        pf_exec = get_pf_exec_filename(ctx, prefetch)
        if pf_exec is None:
            return
        pf_hash = get_pf_hash(ctx, prefetch)
        if pf_hash is None:
            return
        pf_run_count = get_pf_run_count(ctx, prefetch)
        if pf_run_count is None:
            return
        pf_filenames = get_pf_filenames(ctx, prefetch)
        if pf_filenames is None:
            return
        for dtv in get_pf_last_run_times(ctx, prefetch):
            yield {
                'pf_exec': pf_exec,
                'pf_hash': pf_hash,
                'pf_run_time': to_iso_fmt(dtv),
                'pf_run_count': pf_run_count,
                'pf_filenames': pf_filenames,
            }


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob(_PATTERN):
        if not filepath.is_file():
            continue
        if not check_file_signature(filepath):
            _LOGGER.warning("prefetch signature check failed: %s", filepath)
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    yield from _parse_prefetch(ctx)


DISSECTOR = Dissector(
    slug='windows_prefetch',
    tags={Tag.WINDOWS},
    columns=[
        Column('pf_exec', DataType.STR),
        Column('pf_hash', DataType.STR),
        Column('pf_run_time', DataType.STR),
        Column('pf_run_count', DataType.INT),
        Column('pf_filenames', DataType.STR),
    ],
    description="Prefetch",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
