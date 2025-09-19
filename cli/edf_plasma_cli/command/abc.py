"""Base for command implementation"""

from enum import Enum
from json import dumps

from rich.box import ROUNDED
from rich.console import Console
from rich.table import Column, Table

CONSOLE = Console()


class Format(Enum):
    """Output format"""

    RICH = 'rich'
    JSON = 'json'


class FileFormat(Enum):
    """File format"""

    CSV = 'csv'
    JSONL = 'jsonl'


def display_table(out_fmt: Format, headers, rows, **kwargs):
    """Build and print table"""
    final_kwargs = {
        'box': ROUNDED,
        'row_styles': ['dim', ''],
    }
    final_kwargs.update(kwargs)
    if out_fmt == Format.RICH:
        final_headers = [
            Column(header) if isinstance(header, str) else Column(**header)
            for header in headers
        ]
        table = Table(*final_headers, **final_kwargs)
        for row in rows:
            table.add_row(*row)
        CONSOLE.print(table)
        return
    for row in rows:
        print(dumps(dict(zip(headers, row))))
