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

from .helper import parse_pe, pe_fun_is_ctor_dtor, select_pe_impl


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    pef = parse_pe(ctx)
    digest = digest_from_filepath(HashingAlgorithm.SHA256, ctx.filepath)
    for function in pef.functions:
        pe_fun_role = pe_fun_is_ctor_dtor(function)
        if pe_fun_role is None:
            continue
        yield {
            'pe_sha256': digest,
            'pe_fun_role': pe_fun_role,
            'pe_fun_name': function.name,
            'pe_fun_addr': f'{function.address:#018x}',
        }


DISSECTOR = Dissector(
    slug='pe_ctor_dtor',
    tags={Tag.WINDOWS, Tag.PE},
    columns=[
        Column('pe_sha256', DataType.STR),
        Column('pe_fun_role', DataType.STR),
        Column('pe_fun_name', DataType.STR),
        Column('pe_fun_addr', DataType.STR),
    ],
    description="PE constructors and destructors",
    select_impl=select_pe_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
