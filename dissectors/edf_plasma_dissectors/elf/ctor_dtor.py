"""PE constructor dissector"""

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

from .helper import elf_fun_is_ctor_dtor, parse_elf, select_elf_impl


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    elf = parse_elf(ctx)
    digest = digest_from_filepath(HashingAlgorithm.SHA256, ctx.filepath)
    for function in elf.functions:
        elf_fun_role = elf_fun_is_ctor_dtor(function)
        if elf_fun_role is None:
            continue
        yield {
            'elf_sha256': digest,
            'elf_fun_role': elf_fun_role,
            'elf_fun_name': function.name,
            'elf_fun_addr': f'{function.address:#018x}',
        }


DISSECTOR = Dissector(
    slug='elf_ctor_dtor',
    tags={Tag.LINUX, Tag.ELF},
    columns=[
        Column('elf_sha256', DataType.STR),
        Column('elf_fun_role', DataType.STR),
        Column('elf_fun_name', DataType.STR),
        Column('elf_fun_addr', DataType.STR),
    ],
    description="ELF constructors and destructors",
    select_impl=select_elf_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
