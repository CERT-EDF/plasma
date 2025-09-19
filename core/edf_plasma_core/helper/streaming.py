"""Streaming helpers"""

from gzip import open as gzip_open
from pathlib import Path

from .typing import StringIterator

DEFAULT_CHUNK_SIZE = 64 * 1024


def lines_from_filepath(
    filepath: Path, encoding='utf-8', errors=None
) -> StringIterator:
    """Stream lines from file"""
    with filepath.open('r', encoding=encoding, errors=errors) as fobj:
        yield from fobj


def lines_from_gz_filepath(
    filepath: Path, encoding='utf-8', errors=None
) -> StringIterator:
    """Stream lines from gzipped file"""
    with gzip_open(filepath, 'rt', encoding=encoding, errors=errors) as fobj:
        yield from fobj


def chunks_from_filepath(filepath: Path, chunksize=DEFAULT_CHUNK_SIZE):
    """Stream chunks from filepath"""
    with filepath.open('rb') as fobj:
        while True:
            chunk = fobj.read(chunksize)
            if not chunk:
                break
            yield chunk
