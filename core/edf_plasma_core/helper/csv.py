"""CSV operations helper"""

from csv import QUOTE_MINIMAL, DictReader, DictWriter, field_size_limit
from gzip import open as gzip_open
from pathlib import Path
from sys import maxsize

from ..helper.typing import RecordIterator, StringList

field_size_limit(maxsize)


def _read_csv_fobj(fobj) -> RecordIterator:
    csv_reader = DictReader(
        fobj,
        restval='',
        quoting=QUOTE_MINIMAL,
        delimiter=',',
        quotechar='"',
        escapechar='\\',
        doublequote=True,
    )
    yield from csv_reader


def _write_csv_fobj(fobj, fieldnames: StringList, records: RecordIterator):
    csv_writer = DictWriter(
        fobj,
        fieldnames=fieldnames,
        restval='',
        quoting=QUOTE_MINIMAL,
        delimiter=',',
        quotechar='"',
        escapechar='\\',
        doublequote=True,
        extrasaction='ignore',
    )
    csv_writer.writeheader()
    for record in records:
        csv_writer.writerow(record)


def read_csv_gz(filepath: Path) -> RecordIterator:
    """Iterate over gzipped CSV records"""
    with gzip_open(filepath, 'rt', encoding='utf-8', newline='') as fobj:
        yield from _read_csv_fobj(fobj)


def write_csv_gz(
    filepath: Path, fieldnames: StringList, records: RecordIterator
):
    """Write records to gzipped CSV"""
    with gzip_open(filepath, 'wt', encoding='utf-8', newline='') as fobj:
        _write_csv_fobj(fobj, fieldnames, records)
