"""Linux history Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import from_unix_timestamp, to_iso_fmt
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.streaming import lines_from_filepath
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, Record, RecordIterator

_ZSH_TS_PATTERN = regexp(r':\s+(?P<timestamp>\d+):\d+;(?P<command>.*)')
_BASH_TS_PATTERN = regexp(r'#(?P<timestamp>\d+)')
_GLOB_PATTERNS = (
    'root/.*_history',
    'home/*/.*_history',
    # velociraptor collected files have an url-encoded dot
    'root/%2E*_history',
    'home/*/%2E*_history',
)


def _parse_default(line: str, _state: dict) -> Record:
    if line.startswith('#'):
        return None
    return {
        'hist_time': '',
        'hist_command': line,
    }


def _parse_zsh(line: str, _state: dict) -> Record:
    match = _ZSH_TS_PATTERN.fullmatch(line)
    if not match:
        return None
    hist_time = int(match.group('timestamp')) * 1_000_000
    return {
        'hist_time': to_iso_fmt(from_unix_timestamp(hist_time)),
        'hist_command': match.group('command'),
    }


def _parse_bash(line: str, state: dict) -> Record:
    match = _BASH_TS_PATTERN.fullmatch(line)
    if match:
        hist_time = int(match.group('timestamp')) * 1_000_000
        state['hist_time'] = to_iso_fmt(from_unix_timestamp(hist_time))
        return None
    return {
        'hist_time': state.get('hist_time', ''),
        'hist_command': line,
    }


_PARSER_STRATEGY = {
    '%2Ezsh_history': _parse_zsh,
    '%2Ebash_history': _parse_bash,
}


def _select_impl(directory: Path) -> PathIterator:
    for fnmatch_pattern in _GLOB_PATTERNS:
        for filepath in directory.rglob(fnmatch_pattern):
            if not filepath.is_file():
                continue
            yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    state = {}
    parse_line = _PARSER_STRATEGY.get(ctx.filepath.name, _parse_default)
    for line in lines_from_filepath(ctx.filepath, errors='ignore'):
        line = line.replace('\x00', ' ').strip()
        record = parse_line(line, state)
        if not record:
            continue
        yield record


DISSECTOR = Dissector(
    slug='linux_history',
    tags={Tag.LINUX},
    columns=[
        Column('hist_time', DataType.STR),
        Column('hist_command', DataType.STR),
    ],
    description="*_history files",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
