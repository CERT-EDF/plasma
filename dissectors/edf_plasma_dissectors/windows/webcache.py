"""Windows WebCacheV01.dat history artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import from_win32_timestamp, to_iso_fmt
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

from .helper.esedb import (
    check_file_signature,
    iter_ese_table_records_as_dicts,
    open_file_object,
)

_LOGGER = get_logger('dissectors.windows.webcache')
_PATTERN = ci_glob_pattern('WebCacheV01.dat')
_SUPPORTED_NAMES = {'History', 'Cookies', 'iedownload'}


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob(_PATTERN):
        if not filepath.is_file():
            continue
        if not check_file_signature(filepath):
            _LOGGER.warning("webcache signature check failed: %s", filepath)
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open('rb') as fobj:
        webcache = open_file_object(ctx, fobj)
        if webcache is None:
            return
        for container in iter_ese_table_records_as_dicts(
            ctx, webcache, 'Containers'
        ):
            name = container['Name']
            if name not in _SUPPORTED_NAMES and not name.startswith('MSHist'):
                continue
            cid = container['ContainerId']
            for record in iter_ese_table_records_as_dicts(
                ctx, webcache, f'Container_{cid}'
            ):
                yield {
                    'hist_action': 'visit',
                    'hist_url': record['Url'],
                    'hist_time': to_iso_fmt(
                        from_win32_timestamp(record['AccessedTime'] / 10)
                    ),
                    'hist_content': name,
                }


DISSECTOR = Dissector(
    slug='windows_webcache',
    tags={Tag.WINDOWS},
    columns=[
        Column('hist_action', DataType.STR),
        Column('hist_url', DataType.STR),
        Column('hist_time', DataType.STR),
        Column('hist_content', DataType.STR),
    ],
    description="WebCacheV01.dat",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
