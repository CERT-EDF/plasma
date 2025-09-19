"""PE section dissector"""

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

from .helper import (
    parse_pe,
    pe_section_is_code,
    pe_section_perm,
    select_pe_impl,
)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    pef = parse_pe(ctx)
    digest = digest_from_filepath(HashingAlgorithm.SHA256, ctx.filepath)
    for section in pef.sections:
        yield {
            'pe_sha256': digest,
            'pe_s_name': section.name,
            'pe_s_offset': f'{section.offset:#018x}',
            'pe_s_size': section.size,
            'pe_s_vaddr': f'{section.virtual_address:#018x}',
            'pe_s_vsize': section.virtual_size,
            'pe_s_entropy': section.entropy,
            'pe_s_perm': pe_section_perm(section),
            'pe_s_is_code': pe_section_is_code(section),
        }


DISSECTOR = Dissector(
    slug='pe_section',
    tags={Tag.WINDOWS, Tag.PE},
    columns=[
        Column('pe_sha256', DataType.STR),
        Column('pe_s_name', DataType.STR),
        Column('pe_s_offset', DataType.STR),
        Column('pe_s_size', DataType.INT),
        Column('pe_s_vaddr', DataType.STR),
        Column('pe_s_vsize', DataType.INT),
        Column('pe_s_entropy', DataType.FLOAT),
        Column('pe_s_perm', DataType.STR),
        Column('pe_s_is_code', DataType.BOOL),
    ],
    description="PE sections",
    select_impl=select_pe_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
