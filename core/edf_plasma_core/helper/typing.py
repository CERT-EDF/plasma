"""Typing helper"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from yarl import URL

Record = dict[str, Any]
StringSet = set[str]
StringList = list[str]
URLIterator = Iterator[URL]
PathIterator = Iterator[Path]
StringIterator = Iterator[str]
RecordIterator = Iterator[Record]
