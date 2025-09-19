"""SSHPubkey dissector"""

from pathlib import Path
from re import compile as regex

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_GLOB_PATTERN = ci_glob_pattern('*.pub')
_PATTERN = regex(
    r'(?P<encryption>(sk\-|ssh\-|ecdsa\-)[^\s]+)\s(?P<data>[^\s]+)\s(?P<comment>.*)'
)


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob(_GLOB_PATTERN):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open() as file:
        for line in file:
            match = _PATTERN.search(line)
            if not match:
                ctx.register_error(
                    f"File format error, failed to match SSH PubKey line {line}"
                )
                continue
            yield {
                'ssh_pub_key_encryption': match.group('encryption'),
                'ssh_pub_key_data': match.group('data'),
                'ssh_pub_key_comment': match.group('comment'),
            }


DISSECTOR = Dissector(
    slug='generic_ssh_pub_key',
    tags={Tag.GENERIC, Tag.WINDOWS, Tag.LINUX},
    columns=[
        Column('ssh_pub_key_encryption', DataType.STR),
        Column('ssh_pub_key_data', DataType.STR),
        Column('ssh_pub_key_comment', DataType.STR),
    ],
    description="SSH public key",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
