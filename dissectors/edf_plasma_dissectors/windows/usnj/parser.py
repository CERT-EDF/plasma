"""USNJ parser"""

from construct import Int16ul, Int32ul, Int64ul, Struct
from edf_plasma_core.dissector import DissectionContext
from edf_plasma_core.helper.datetime import from_win32_timestamp, to_iso_fmt

from ..mft.parser import (
    parse_file_name_flags,
    parse_usnj_entry_reason,
    parse_usnj_entry_source,
)

USN_RECORD_V2_HDR = Struct(
    'entry_sz' / Int32ul,
    'major_version' / Int16ul,
    'minor_version' / Int16ul,
    'mft_ref' / Int64ul,
    'mft_ref_parent' / Int64ul,
    'offset' / Int64ul,
    'timestamp' / Int64ul,
    'reason' / Int32ul,
    'source_info' / Int32ul,
    'security_id' / Int32ul,
    'file_flags' / Int32ul,
    'filename_sz' / Int16ul,
)
USN_RECORD_V2_HDR_SZ = USN_RECORD_V2_HDR.sizeof()


def _parse_mft_ref(buf):
    seq_num = (buf >> 48) & 0xFFFF
    ent_num = buf & 0xFFFFFFFFFFFF
    return seq_num, ent_num


def _find_next_entry(fobj) -> bool:
    while True:
        entry_sz_bytes = fobj.peek(4)
        if not entry_sz_bytes:
            return False
        entry_sz = Int32ul.parse(entry_sz_bytes)
        if entry_sz:
            return True
        fobj.read(4)


def usnj_records(ctx: DissectionContext):
    """Retrieve USNJ records from context"""
    total_size = ctx.filepath.stat().st_size
    with ctx.filepath.open('rb') as fobj:
        while True:
            if not _find_next_entry(fobj):
                break
            offset = fobj.tell()
            usnj_ent_hdr_bytes = fobj.read(USN_RECORD_V2_HDR_SZ)
            usnj_ent_hdr = USN_RECORD_V2_HDR.parse(usnj_ent_hdr_bytes)
            # perform consistency check before going further
            if (
                usnj_ent_hdr.major_version not in (2, 3, 4)
                or usnj_ent_hdr.minor_version != 0
            ):
                if offset + 1 + USN_RECORD_V2_HDR_SZ >= total_size:
                    break
                fobj.seek(offset + 1)
                continue
            filename = fobj.read(usnj_ent_hdr.filename_sz).decode('utf-16le')
            padding_sz = (
                usnj_ent_hdr.entry_sz
                - USN_RECORD_V2_HDR_SZ
                - usnj_ent_hdr.filename_sz
            )
            if padding_sz:
                fobj.read(padding_sz)
            usnj_mft_seq_num, usnj_mft_ent_num = _parse_mft_ref(
                usnj_ent_hdr.mft_ref
            )
            (
                usnj_mft_parent_seq_num,
                usnj_mft_parent_ent_num,
            ) = _parse_mft_ref(usnj_ent_hdr.mft_ref_parent)
            yield {
                'usnj_time': to_iso_fmt(
                    from_win32_timestamp(usnj_ent_hdr.timestamp // 10)
                ),
                'usnj_reason': parse_usnj_entry_reason(usnj_ent_hdr.reason),
                'usnj_source': parse_usnj_entry_source(
                    usnj_ent_hdr.source_info
                ),
                'usnj_filename': filename,
                'usnj_file_flags': parse_file_name_flags(
                    usnj_ent_hdr.file_flags
                ),
                'usnj_mft_seq_num': usnj_mft_seq_num,
                'usnj_mft_ent_num': usnj_mft_ent_num,
                'usnj_mft_parent_seq_num': usnj_mft_parent_seq_num,
                'usnj_mft_parent_ent_num': usnj_mft_parent_ent_num,
            }
