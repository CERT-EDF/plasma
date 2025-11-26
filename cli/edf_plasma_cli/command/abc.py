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


def _display_table_rich(headers, rows, **kwargs):
    kwargs.update({'box': ROUNDED, 'row_styles': ['dim', '']})
    headers = [
        Column(header) if isinstance(header, str) else Column(**header)
        for header in headers
    ]
    table = Table(*headers, **kwargs)
    for row in rows:
        table.add_row(*row)
    CONSOLE.print(table)


def _display_table_json(headers, rows, **kwargs):
    headers = [
        header if isinstance(header, str) else header['header']
        for header in headers
    ]
    for row in rows:
        print(dumps(dict(zip(headers, row))))


_DISPLAY_TABLE_STRATEGY = {
    Format.RICH: _display_table_rich,
    Format.JSON: _display_table_json,
}


def display_table(out_fmt: Format, headers, rows, **kwargs):
    """Build and print table"""
    _DISPLAY_TABLE_STRATEGY[out_fmt](headers, rows, **kwargs)
