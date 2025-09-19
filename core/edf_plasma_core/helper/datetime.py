"""Datetime helper"""

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from enum import Flag
from itertools import groupby
from operator import itemgetter

REF_OLE = datetime(1899, 12, 30, tzinfo=timezone.utc)
REF_UNIX = datetime(1970, 1, 1, tzinfo=timezone.utc)
REF_WIN32 = datetime(1601, 1, 1, tzinfo=timezone.utc)


class MACB(Flag):
    """MACB flag"""

    M = 0x01
    A = 0x02
    C = 0x04
    B = 0x08


_MACB_VALUES = [flag.value for flag in MACB]


def with_utc(dtv: datetime) -> datetime:
    """Set UTC timezone for given unaware datetime value"""
    return dtv.replace(tzinfo=timezone.utc)


def utc_now() -> datetime:
    """Get current UTC datetime value"""
    return datetime.now(timezone.utc)


def to_utc(dtv: datetime) -> datetime:
    """Convert non-utc datetime to utc datetime"""
    return dtv.astimezone(timezone.utc)


def to_iso_fmt(dtv: datetime) -> str:
    """Convert datetime value to ISO string"""
    return dtv.isoformat()


def from_iso_fmt(isofmt: str) -> datetime:
    """Convert ISO string to datetime value"""
    return datetime.fromisoformat(isofmt)


def from_ole_timestamp(microseconds: int) -> datetime:
    """OLE microseconds timestamp as datetime"""
    return REF_OLE + timedelta(microseconds=microseconds)


def from_unix_timestamp(microseconds: int) -> datetime:
    """UNIX microseconds timestamp as datetime"""
    return REF_UNIX + timedelta(microseconds=microseconds)


def from_win32_timestamp(microseconds: int) -> datetime:
    """WIN32 microseconds timestamp as datetime"""
    return REF_WIN32 + timedelta(microseconds=microseconds)


def _macb_string(macb: MACB):
    return ''.join(
        [
            'M' if MACB.M in macb else '_',
            'A' if MACB.A in macb else '_',
            'C' if MACB.C in macb else '_',
            'B' if MACB.B in macb else '_',
        ]
    )


def macb_groups(
    mdtv: datetime, adtv: datetime, cdtv: datetime, bdtv: datetime
) -> Iterator[tuple[datetime, str]]:
    """Create MACB groups"""
    dtvs = [mdtv, adtv, cdtv, bdtv]
    for dtv, items in groupby(zip(dtvs, _MACB_VALUES), key=itemgetter(0)):
        if dtv is None:
            continue
        yield dtv, _macb_string(MACB(sum(item[1] for item in items)))
