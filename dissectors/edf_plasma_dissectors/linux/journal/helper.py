"""Systemd journal wrapper"""

from pathlib import Path

from edf_plasma_core.dissector import DissectionContext
from edf_plasma_core.helper.importing import lazy_import
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.typing import PathIterator


lazy_journal = lazy_import('systemd.journal')
SYSTEMD_AVAILABLE = lazy_journal is not None


def select_journal_impl(directory: Path) -> PathIterator:
    """Select systemd journal files"""
    pattern = '*.journal'
    yield from select(directory, pattern)


def journal_reader(ctx: DissectionContext):
    """Instanciate journal reader for given dissection context"""
    try:
        return lazy_journal.Reader(files=[str(ctx.filepath)])
    except OSError:
        ctx.register_error(
            f"File format error, the systemd.journal library couldn't read the file: {ctx.filepath}"
        )
    return None
