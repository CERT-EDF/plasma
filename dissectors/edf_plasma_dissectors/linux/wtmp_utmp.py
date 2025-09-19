"""Linux Wtmp/Utmp/Btmp Dissector"""

from collections.abc import Iterator
from pathlib import Path

from construct import (
    Aligned,
    Array,
    Bytes,
    Container,
    Int16sl,
    Int32sl,
    Struct,
)
from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import from_unix_timestamp, to_iso_fmt
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_GLOB_PATTERNS = (
    'utmp*',
    'wtmp*',
    'btmp*',
)

ExitStatus = Struct(
    'e_termination' / Int16sl,
    'e_exit' / Int16sl,
)
Timeval = Struct(
    'tv_sec' / Int32sl,
    'tv_usec' / Int32sl,
)
UTMPRecord = Struct(
    'ut_type' / Aligned(4, Int16sl),
    'ut_pid' / Int32sl,
    'ut_line' / Bytes(32),
    'ut_id' / Bytes(4),
    'ut_user' / Bytes(32),
    'ut_host' / Bytes(256),
    'ut_exit' / ExitStatus,
    'ut_session' / Int32sl,
    'ut_tv' / Timeval,
    'ut_addr_v6' / Array(4, Int32sl),
    '_dummy' / Bytes(20),
)


def _utmp_read(utmp_path: Path) -> Iterator[Container]:
    with utmp_path.open('rb') as file:
        while True:
            data = file.read(UTMPRecord.sizeof())
            if len(data) != UTMPRecord.sizeof():
                break
            yield UTMPRecord.parse(data)


def _select_impl(directory: Path) -> PathIterator:
    for pattern in _GLOB_PATTERNS:
        for filepath in directory.rglob(pattern):
            if not filepath.is_file():
                continue
            yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    for entry in _utmp_read(ctx.filepath):
        timestamp = float(entry.ut_tv.tv_sec)
        timestamp = from_unix_timestamp(timestamp * 1000 * 1000)
        yield {
            'ut_type': entry.ut_type,
            'ut_pid': entry.ut_pid,
            'ut_user': str(entry.ut_user.replace(b'\x00', b''))[2:-1],
            'ut_line': str(entry.ut_line.replace(b'\x00', b''))[2:-1],
            'ut_host': str(entry.ut_host.replace(b'\x00', b''))[2:-1],
            'ut_time': to_iso_fmt(timestamp),
        }


DISSECTOR = Dissector(
    slug='linux_wtmp_utmp',
    tags={Tag.LINUX},
    columns=[
        Column('ut_type', DataType.INT),
        Column('ut_pid', DataType.INT),
        Column('ut_user', DataType.STR),
        Column('ut_line', DataType.STR),
        Column('ut_host', DataType.STR),
        Column('ut_time', DataType.STR),
    ],
    description="utmp, wtmp and btmp binary logs",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
