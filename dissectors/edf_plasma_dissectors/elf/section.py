"""ELF section dissector"""

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

from .helper import elf_section_perm, parse_elf, select_elf_impl


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    elf = parse_elf(ctx)
    digest = digest_from_filepath(HashingAlgorithm.SHA256, ctx.filepath)
    for section in elf.sections:
        yield {
            'elf_sha256': digest,
            'elf_sec_name': section.name,
            'elf_sec_offset': f'{section.offset:#018x}',
            'elf_sec_size': section.size,
            'elf_sec_vaddr': f'{section.virtual_address:#018x}',
            'elf_sec_entropy': section.entropy,
            'elf_sec_perm': elf_section_perm(section),
        }


DISSECTOR = Dissector(
    slug='elf_section',
    tags={Tag.LINUX, Tag.ELF},
    columns=[
        Column('elf_sha256', DataType.STR),
        Column('elf_sec_name', DataType.STR),
        Column('elf_sec_offset', DataType.STR),
        Column('elf_sec_size', DataType.INT),
        Column('elf_sec_vaddr', DataType.STR),
        Column('elf_sec_entropy', DataType.FLOAT),
        Column('elf_sec_perm', DataType.STR),
    ],
    description="ELF binary sections",
    select_impl=select_elf_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
