"""ELF exported symbols dissector"""

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

from .helper import parse_elf, select_elf_impl


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    elf = parse_elf(ctx)
    digest = digest_from_filepath(HashingAlgorithm.SHA256, ctx.filepath)
    for symbol in elf.exported_symbols:
        yield {
            'elf_sha256': digest,
            'elf_esym_name': symbol.demangled_name,
            'elf_esym_type': str(symbol.type).rsplit('.', 1)[-1],
            'elf_esym_offset': f'{symbol.value:#018x}',
            'elf_esym_section': symbol.section.name if symbol.section else '',
        }


DISSECTOR = Dissector(
    slug='elf_export',
    tags={Tag.LINUX, Tag.ELF},
    columns=[
        Column('elf_sha256', DataType.STR),
        Column('elf_esym_name', DataType.STR),
        Column('elf_esym_type', DataType.STR),
        Column('elf_esym_offset', DataType.STR),
        Column('elf_esym_section', DataType.STR),
    ],
    description="ELF binary exported symbols",
    select_impl=select_elf_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
