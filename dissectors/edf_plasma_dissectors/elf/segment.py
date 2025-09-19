"""ELF segment dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.cryptography import entropy_from_bytes
from edf_plasma_core.helper.hashing import (
    HashingAlgorithm,
    digest_from_filepath,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from .helper import elf_segment_perm, parse_elf, select_elf_impl


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    elf = parse_elf(ctx)
    digest = digest_from_filepath(HashingAlgorithm.SHA256, ctx.filepath)
    for segment in elf.segments:
        yield {
            'elf_sha256': digest,
            'elf_seg_type': str(segment.type).rsplit('.', 1)[-1],
            'elf_seg_offset': f'{segment.file_offset:#018x}',
            'elf_seg_size': segment.physical_size,
            'elf_seg_vaddr': f'{segment.virtual_address:#018x}',
            'elf_seg_vsize': segment.virtual_size,
            'elf_seg_entropy': entropy_from_bytes(segment.content.tobytes()),
            'elf_seg_perm': elf_segment_perm(segment),
        }


DISSECTOR = Dissector(
    slug='elf_segment',
    tags={Tag.LINUX, Tag.ELF},
    columns=[
        Column('elf_sha256', DataType.STR),
        Column('elf_seg_type', DataType.STR),
        Column('elf_seg_offset', DataType.STR),
        Column('elf_seg_size', DataType.INT),
        Column('elf_seg_vaddr', DataType.STR),
        Column('elf_seg_vsize', DataType.INT),
        Column('elf_seg_entropy', DataType.FLOAT),
        Column('elf_seg_perm', DataType.STR),
    ],
    description="ELF binary segments",
    select_impl=select_elf_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
