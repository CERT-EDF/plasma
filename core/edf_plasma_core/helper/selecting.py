"""Selection helper"""

from os import R_OK, access
from pathlib import Path

from .logging import get_logger

_LOGGER = get_logger('core.helper.selecting')


def select(directory: Path, pattern: str):
    """Select readable files from directory matching pattern"""
    for filepath in directory.rglob(pattern):
        if not filepath.is_file():
            continue
        if not access(filepath, R_OK):
            _LOGGER.error("permission denied: %s", filepath)
            continue
        yield filepath
