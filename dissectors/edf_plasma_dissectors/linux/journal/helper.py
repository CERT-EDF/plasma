"""Systemd journal wrapper"""

from edf_plasma_core.dissector import DissectionContext
from edf_plasma_core.helper.importing import lazy_import

lazy_journal = lazy_import('systemd.journal')
SYSTEMD_AVAILABLE = lazy_journal is not None


def journal_reader(ctx: DissectionContext):
    """Instanciate journal reader for given dissection context"""
    try:
        return lazy_journal.Reader(files=[str(ctx.filepath)])
    except OSError:
        ctx.register_error(
            f"File format error, the systemd.journal library couldn't read the file: {ctx.filepath}"
        )
    return None
