"""Systemd journal wrapper"""

from edf_plasma_core.dissector import DissectionContext
from systemd.journal import Reader


def journal_reader(ctx: DissectionContext) -> Reader | None:
    """Instanciate journal reader for given dissection context"""
    try:
        return Reader(files=[str(ctx.filepath)])
    except OSError:
        ctx.register_error(
            f"File format error, the systemd.journal library couldn't read the file: {ctx.filepath}"
        )
    return None
