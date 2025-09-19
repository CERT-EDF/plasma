"""Filtering helper"""

from dataclasses import dataclass, field

from .typing import StringIterator, StringSet


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


@dataclass
class Filter:
    """Include/exclude filter"""

    include: StringSet = field(default_factory=set)
    exclude: StringSet = field(default_factory=set)

    def accept(self, candidate: str | set[str]) -> bool:
        """Determine if candidate is accepted"""
        return not self.reject(candidate)

    def reject(self, candidate: str | set[str]) -> bool:
        """Determine if candidate is rejected"""
        if isinstance(candidate, set):
            return (self.exclude and self.exclude.intersection(candidate)) or (
                self.include and not self.include.intersection(candidate)
            )
        return (self.exclude and candidate in self.exclude) or (
            self.include and candidate not in self.include
        )
