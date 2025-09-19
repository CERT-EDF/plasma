"""ELF information dissector"""

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
    yield {
        'elf_md5': digest_from_filepath(HashingAlgorithm.MD5, ctx.filepath),
        'elf_sha1': digest_from_filepath(HashingAlgorithm.SHA1, ctx.filepath),
        'elf_sha256': digest_from_filepath(
            HashingAlgorithm.SHA256, ctx.filepath
        ),
        'elf_size': ctx.filepath.stat().st_size,
        'elf_filename': ctx.filepath.name,
        'elf_is_pie': elf.is_pie,
        'elf_entrypoint': f'{elf.entrypoint:#018x}',
        'elf_interpreter': elf.interpreter,
    }


DISSECTOR = Dissector(
    slug='elf_info',
    tags={Tag.LINUX, Tag.ELF},
    columns=[
        Column('elf_md5', DataType.STR),
        Column('elf_sha1', DataType.STR),
        Column('elf_sha256', DataType.STR),
        Column('elf_size', DataType.INT),
        Column('elf_filename', DataType.STR),
        Column('elf_is_pie', DataType.BOOL),
        Column('elf_entrypoint', DataType.STR),
        Column('elf_interpreter', DataType.STR),
    ],
    description="ELF information",
    select_impl=select_elf_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
