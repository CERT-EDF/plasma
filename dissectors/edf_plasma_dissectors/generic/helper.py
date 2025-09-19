"""SQL parsing"""

from dataclasses import dataclass
from pathlib import Path
from sqlite3 import DatabaseError, connect
from typing import Any

from edf_plasma_core.dissector import DissectionContext

SQLITE3_MAGIC = b'SQLite format 3'


def check_file_signature(filepath: Path) -> bool:
    """Check that filepath first bytes match SQLite3 magic value"""
    with filepath.open('rb') as fobj:
        return fobj.read(len(SQLITE3_MAGIC)) == SQLITE3_MAGIC


@dataclass
class SQLiteDatabase:
    ctx: DissectionContext
    connection: Any = None

    def __enter__(self):
        self.connection = connect(self.ctx.filepath)
        return self

    def __exit__(self, exc_typ, exc_val, exc_trb):
        self.connection.close()

    def execute(
        self,
        stmt: str,
    ):
        """Execute SQL statement"""
        try:
            yield from self.connection.execute(stmt)
        except DatabaseError as exc:
            self.ctx.register_error(f"dissector query failed: {exc}")
            return
