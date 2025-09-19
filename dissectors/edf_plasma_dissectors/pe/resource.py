"""PE constructor dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.cryptography import entropy_from_bytes
from edf_plasma_core.helper.hashing import (
    HashingAlgorithm,
    digest_from_bytes,
    digest_from_filepath,
)
from edf_plasma_core.helper.identifying import (
    Magika,
    identify_bytes,
    instanciate_magika,
)
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from .helper import parse_pe, select_pe_impl

_LOGGER = get_logger('dissectors.pe.resource')


def _get_child_node(child_node):
    assert child_node.numberof_id_entries == 1
    return next(child_node.childs)


def _best_ident(data: bytes, magika: Magika) -> str:
    ident_result = identify_bytes(data, magika=magika)
    if ident_result.magika_output != 'application/octet-stream':
        return ident_result.magika_output
    return ident_result.magic_output


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    pef = parse_pe(ctx)
    magika = instanciate_magika()
    digest = digest_from_filepath(HashingAlgorithm.SHA256, ctx.filepath)
    if not pef.has_resources:
        _LOGGER.warning("portable executable does not have any resource")
        return
    rsrc_mgr = pef.resources_manager
    for rsrc_type in rsrc_mgr.types:
        rsrc_node = rsrc_mgr.get_node_type(rsrc_type)
        for child_node in rsrc_node.childs:
            try:
                node = _get_child_node(child_node)
            except AssertionError:
                continue
            rsrc_data = node.content.tobytes()
            yield {
                'pe_sha256': digest,
                'pe_r_type': str(rsrc_type).rsplit('.', 1)[-1],
                'pe_r_size': len(rsrc_data),
                'pe_r_entropy': entropy_from_bytes(rsrc_data),
                'pe_r_mime_type': _best_ident(rsrc_data, magika),
                'pe_r_md5': digest_from_bytes(HashingAlgorithm.MD5, rsrc_data),
                'pe_r_sha1': digest_from_bytes(
                    HashingAlgorithm.SHA1, rsrc_data
                ),
                'pe_r_sha256': digest_from_bytes(
                    HashingAlgorithm.SHA256, rsrc_data
                ),
            }


DISSECTOR = Dissector(
    slug='pe_resource',
    tags={Tag.WINDOWS, Tag.PE},
    columns=[
        Column('pe_sha256', DataType.STR),
        Column('pe_r_type', DataType.STR),
        Column('pe_r_size', DataType.INT),
        Column('pe_r_entropy', DataType.FLOAT),
        Column('pe_r_mime_type', DataType.STR),
        Column('pe_r_md5', DataType.STR),
        Column('pe_r_sha1', DataType.STR),
        Column('pe_r_sha256', DataType.STR),
    ],
    description="PE resources",
    select_impl=select_pe_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
