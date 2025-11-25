"""Firefox history artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import from_unix_timestamp, to_iso_fmt
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

from .helper import SQLiteDatabase, check_file_signature

_LOGGER = get_logger('dissectors.generic.chromium')
_FIREFOX_VISIT_SQL_STMT = '''
SELECT visit_date,url
FROM moz_places
LEFT JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
WHERE visit_date IS NOT NULL
'''
_FIREFOX_DOWNLOAD_SQL_STMT = '''
SELECT dateAdded,url,content
FROM moz_places
LEFT JOIN moz_annos ON moz_places.id = moz_annos.place_id
WHERE content IS NOT NULL
'''


def _parse_firefox_db(sql_db):
    """Extract web browsing and download history from firefox database"""
    for row in sql_db.execute(_FIREFOX_VISIT_SQL_STMT):
        yield {
            'hist_action': 'visit',
            'hist_time': to_iso_fmt(from_unix_timestamp(row[0])),
            'hist_url': row[1],
            'hist_content': '',
        }
    for row in sql_db.execute(_FIREFOX_DOWNLOAD_SQL_STMT):
        yield {
            'hist_action': 'download',
            'hist_time': to_iso_fmt(from_unix_timestamp(row[0])),
            'hist_url': row[1],
            'hist_content': row[2],
        }


def _select_impl(directory: Path) -> PathIterator:
    pattern = ci_glob_pattern('places.sqlite')
    for filepath in select(directory, pattern):
        if not check_file_signature(filepath):
            _LOGGER.warning("signature check failed for: %s", filepath)
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with SQLiteDatabase(ctx=ctx) as sql_db:
        yield from _parse_firefox_db(sql_db)


DISSECTOR = Dissector(
    slug='generic_firefox_history',
    tags={Tag.GENERIC, Tag.WINDOWS, Tag.LINUX},
    columns=[
        Column('hist_action', DataType.STR),
        Column('hist_time', DataType.STR),
        Column('hist_url', DataType.STR),
        Column('hist_content', DataType.STR),
    ],
    description="Firefox download and visit history",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
