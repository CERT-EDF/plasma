"""Windows SRUDB artifact dissector"""

from pathlib import Path
from struct import unpack

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import (
    from_win32_timestamp,
    timedelta,
    to_iso_fmt,
)
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

from .helper.esedb import (
    check_file_signature,
    iter_ese_table_records_as_dicts,
    open_file_object,
)

_LOGGER = get_logger('dissectors.windows.srudb')
_PATTERN = ci_glob_pattern('SRUDB.dat')


def _parse_app(data: bytes | None) -> str:
    if data is None:
        return 'plasma:empty'
    return data.replace(b'\x00', b'').decode()


def _parse_sid(data: bytes | None) -> str:
    if data is None:
        return 'plasma:empty'
    parts = [data[0]]
    suffix_count = data[1]
    parts.append(unpack('>Q', b'\x00\x00' + data[2:8])[0])
    for suffix_idx in range(suffix_count):
        parts.append(
            unpack('<I', data[8 + suffix_idx * 4 : 8 + (suffix_idx + 1) * 4])[
                0
            ]
        )
    return '-'.join(['S'] + [str(part) for part in parts])


def _srudb_records(ctx: DissectionContext):
    with ctx.filepath.open('rb') as fobj:
        srudb = open_file_object(ctx, fobj)
        if srudb is None:
            return
        # build mapping from SruDbIdMapTable records
        srudb_id_mapping = {
            record['IdIndex']: record['IdBlob']
            for record in iter_ese_table_records_as_dicts(
                ctx, srudb, 'SruDbIdMapTable'
            )
        }
        # parse records from {5C8CF1C7-7257-4F13-B223-970EF5939312}
        for record in iter_ese_table_records_as_dicts(
            ctx, srudb, '{5C8CF1C7-7257-4F13-B223-970EF5939312}'
        ):
            end_time = from_win32_timestamp(int(record['EndTime']) // 10)
            delta = timedelta(milliseconds=int(record['DurationMS']))
            beg_time = end_time - delta
            yield {
                'sru_beg_time': to_iso_fmt(beg_time),
                'sru_end_time': to_iso_fmt(end_time),
                'sru_app': _parse_app(srudb_id_mapping[record['AppId']]),
                'sru_user': _parse_sid(srudb_id_mapping[record['UserId']]),
            }


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob(_PATTERN):
        if not filepath.is_file():
            continue
        if not check_file_signature(filepath):
            _LOGGER.warning("srudb signature check failed: %s", filepath)
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    yield from _srudb_records(ctx)


DISSECTOR = Dissector(
    slug='windows_srudb',
    tags={Tag.WINDOWS},
    columns=[
        Column('sru_beg_time', DataType.STR),
        Column('sru_end_time', DataType.STR),
        Column('sru_app', DataType.STR),
        Column('sru_user', DataType.STR),
    ],
    description="SRUDB.dat",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
