"""Darwin KnowledgeC Dissector"""

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

_LOGGER = get_logger('dissectors.darwin.knowledgec')
_SQL_STMT = '''
SELECT
    ZOBJECT.ZCREATIONDATE AS creation_time,
    ZOBJECT.ZSTARTDATE AS beg_time,
    ZOBJECT.ZENDDATE AS end_time,
    ZSTRUCTUREDMETADATA.*
FROM
    ZOBJECT
JOIN
    ZSTRUCTUREDMETADATA ON ZOBJECT.ZSTRUCTUREDMETADATA = ZSTRUCTUREDMETADATA.Z_PK;
'''


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'knowledgeC.db'
    for filepath in select(directory, pattern):
        if not check_sqlite_signature(filepath):
            _LOGGER.warning("signature check failed for: %s", filepath)
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with SQLiteDatabase(ctx=ctx) as sql_db:
        for row in sql_db.execute(_SQL_STMT):
            dct = dict(row)
            creation_time = dct.pop('creation_time') * 1_000_000
            beg_time = dct.pop('beg_time') * 1_000_000
            end_time = dct.pop('end_time') * 1_000_000
            yield {
                'creation_time': to_iso_fmt(
                    with_utc(from_darwin_timestamp(creation_time))
                ),
                'beg_time': to_iso_fmt(
                    with_utc(from_darwin_timestamp(beg_time))
                ),
                'end_time': to_iso_fmt(
                    with_utc(from_darwin_timestamp(end_time))
                ),
                'data': dumps(dct),
            }


DISSECTOR = Dissector(
    slug='darwin_knowledgec',
    tags={Tag.DARWIN},
    columns=[
        Column('creation_time', DataType.STR),
        Column('beg_time', DataType.STR),
        Column('end_time', DataType.STR),
        Column('data', DataType.STR),
    ],
    description="Extract data from knowledgeC.db",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
