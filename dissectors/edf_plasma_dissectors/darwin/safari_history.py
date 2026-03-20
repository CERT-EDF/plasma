"""Darwin Safari Downloads Dissector"""

from json import dumps
from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import (
    from_darwin_timestamp,
    to_iso_fmt,
    with_utc,
)
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

from ..helper.sqlite import SQLiteDatabase, check_sqlite_signature
from .helper import load_plist

_LOGGER = get_logger('dissectors.darwin.safari_history')
_SAFARI_VISIT_SQL_STMT = '''
SELECT v.visit_time,i.url
FROM history_visits AS v
LEFT JOIN history_items AS i ON v.history_item = i.id
'''


def _select_impl(directory: Path) -> PathIterator:
    patterns = ['Downloads.plist', 'History.db']
    for pattern in patterns:
        for filepath in select(directory, pattern):
            if pattern != 'History.db':
                yield filepath
            if not check_sqlite_signature(filepath):
                _LOGGER.warning("signature check failed for: %s", filepath)
                continue
            yield filepath


def _dissect_history(ctx: DissectionContext) -> RecordIterator:
    with SQLiteDatabase(ctx=ctx) as sql_db:
        for row in sql_db.execute(_SAFARI_VISIT_SQL_STMT):
            darwin_ts = row[0] * 1_000_000
            yield {
                'hist_action': 'visit',
                'hist_time': to_iso_fmt(
                    with_utc(from_darwin_timestamp(darwin_ts))
                ),
                'hist_url': row[1],
                'hist_content': '',
            }


def _dissect_downloads(ctx: DissectionContext) -> RecordIterator:
    data = load_plist(ctx.filepath)
    for item in data['DownloadHistory']:
        yield {
            'hist_action': 'download',
            'hist_time': to_iso_fmt(item['DownloadEntryDateAddedKey']),
            'hist_url': item['DownloadEntryURL'],
            'hist_content': dumps(
                {
                    'path': item['DownloadEntryPath'],
                    'size': item['DownloadEntryProgressTotalToLoad'],
                },
                separators=(',', ':'),
            ),
        }


_DISSECT_STRATEGY = {
    'History.db': _dissect_history,
    'Downloads.plist': _dissect_downloads,
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    dissect_impl = _DISSECT_STRATEGY.get(ctx.filepath.name)
    if not dissect_impl:
        _LOGGER.warning(
            "no dissector implementation for selected file: %s",
            ctx.filepath.name,
        )
        return
    yield from dissect_impl(ctx)


DISSECTOR = Dissector(
    slug='darwin_safari_history',
    tags={Tag.DARWIN},
    columns=[
        Column('hist_action', DataType.STR),
        Column('hist_time', DataType.STR),
        Column('hist_url', DataType.STR),
        Column('hist_content', DataType.STR),
    ],
    description="Safari visit and download history",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
