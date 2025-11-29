"""Filtering helper"""

from .typing import StringIterator


def unique(candidates: StringIterator) -> StringIterator:
    """Yield unique values from generator
    WARNING: memory will keep growing if input generator is infinite
    """
    known: set[str] = set()
    for candidate in candidates:
        if candidate in known:
            continue
        known.add(candidate)
        yield candidate
