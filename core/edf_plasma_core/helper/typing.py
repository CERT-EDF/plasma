"""Typing helper"""

from collections.abc import Iterator
from pathlib import Path
from queue import Queue

from yarl import URL

Record = dict[str, str | bool | int | float | None]
StringSet = set[str]
StringList = list[str]
URLIterator = Iterator[URL]
RecordQueue = Queue[Record | None]
PathIterator = Iterator[Path]
StringIterator = Iterator[str]
RecordIterator = Iterator[Record]
