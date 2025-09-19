"""ELF dynamic entry library dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.hashing import (
    HashingAlgorithm,
    digest_from_filepath,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from .helper import elf_is_dt_needed, parse_elf, select_elf_impl


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    elf = parse_elf(ctx)
    digest = digest_from_filepath(HashingAlgorithm.SHA256, ctx.filepath)
    for entry in elf.dynamic_entries:
        if not elf_is_dt_needed(entry):
            continue
        yield {
            'elf_sha256': digest,
            'elf_lib_name': entry.name,
        }


DISSECTOR = Dissector(
    slug='elf_library',
    tags={Tag.LINUX, Tag.ELF},
    columns=[
        Column('elf_sha256', DataType.STR),
        Column('elf_lib_name', DataType.STR),
    ],
    description="ELF binary needed libraries",
    select_impl=select_elf_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
