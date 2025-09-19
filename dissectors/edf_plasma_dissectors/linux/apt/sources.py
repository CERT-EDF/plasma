"""APT Sources Dissector"""

from collections import defaultdict
from dataclasses import dataclass, field
from functools import partial
from itertools import product
from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.streaming import lines_from_filepath
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_GLOB_PATTERNS = (
    'sources.list',
    'sources.list.d/*.list',
    'sources.list.d/*.sources',
)
_PATTERN = regexp(
    r'(?P<type>[^#\s]+)\s+(\[[^\]]+\]\s+)?(?P<url>[^\s]+)\s+(?P<suite>[^\s]+)\s+(?P<components>.*)'
)
_ENTRY_PATTERN = regexp(r'^(?P<key>Types|URIs|Suites|Components): (?P<val>.*)')


@dataclass
class Group:
    """Source file group"""

    entries: dict[str, list[str]] = field(
        default_factory=partial(defaultdict, list)
    )

    @property
    def ready(self) -> bool:
        """Determine if group can generate records"""
        suites = self.entries['suites']
        if not suites:
            return False
        components = True
        for suite in suites:
            if suite.endswith('/'):
                components = False
                break
        return len(self.entries) == (4 if components else 3)

    def add(self, line: str):
        """Add group entry"""
        match = _ENTRY_PATTERN.search(line)
        if not match:
            return
        key = match.group('key').lower()
        values = list(filter(None, match.group('val').strip().split(' ')))
        if values:
            self.entries[key].extend(values)

    def clear(self):
        """Clear group entries"""
        self.entries.clear()

    def records(self):
        """Generate group records"""
        for src_type, src_url, src_suite, src_component in product(
            self.entries['types'],
            self.entries['uris'],
            self.entries['suites'],
            self.entries['components'] or [''],
        ):
            yield {
                'src_type': src_type,
                'src_url': src_url,
                'src_suite': src_suite,
                'src_component': src_component,
            }


def _parse_line(line: str, prefix: str) -> list[str]:
    if line.startswith(prefix):
        _, items = line.split(prefix, 1)
        return list(filter(None, items.split(' ')))
    return []


def _dissect_sources(ctx: DissectionContext):
    group = Group()
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        group.add(line)
        if group.ready:
            yield from group.records()
            group.clear()
    if group.ready:
        yield from group.records()
        group.clear()


def _dissect_list(ctx: DissectionContext):
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        match = _PATTERN.fullmatch(line)
        if not match:
            continue
        components = match.group('components').strip().split(' ')
        for component in filter(None, components):
            yield {
                'src_type': match.group('type'),
                'src_url': match.group('url'),
                'src_suite': match.group('suite'),
                'src_component': component,
            }


_DISSECT_STRATEGY = {'.sources': _dissect_sources}


def _select_impl(directory: Path) -> PathIterator:
    for fnmatch_pattern in _GLOB_PATTERNS:
        for filepath in directory.rglob(fnmatch_pattern):
            if not filepath.is_file():
                continue
            yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    dissect = _DISSECT_STRATEGY.get(ctx.filepath.suffix, _dissect_list)
    yield from dissect(ctx)


DISSECTOR = Dissector(
    slug='linux_apt_sources',
    tags={Tag.LINUX},
    columns=[
        Column('src_type', DataType.STR),
        Column('src_url', DataType.STR),
        Column('src_suite', DataType.STR),
        Column('src_component', DataType.STR),
    ],
    description="apt sources",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
