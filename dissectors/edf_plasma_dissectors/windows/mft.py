"""Windows MFT artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import macb_groups, to_iso_fmt, with_utc
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

from .helper.fsntfs import mft_metadata_file
from .parser.mft import parse_file_name_flags

_NAMESPACE_DOS = 2
_ATTR_DATA = 0x80
_ATTR_FILE_NAME = 0x30
_REC_TIME = 'mft_e_time'
_REC_MACB = 'mft_e_macb'
_REC_PATH = 'mft_e_path'
_REC_SIZE = 'mft_e_size'
_REC_FLAGS = 'mft_e_flags'


def _parse_mft_entry(mft_entry) -> RecordIterator:
    # parse mft entry attributes
    record = {
        _REC_TIME: '',
        _REC_MACB: '',
        _REC_PATH: '',
        _REC_SIZE: 0,
        _REC_FLAGS: '',
    }
    data_sizes = []
    macb_groups_ = []
    for mft_attrib_idx in range(mft_entry.number_of_attributes):
        mft_entry_attrib = mft_entry.get_attribute(mft_attrib_idx)
        if mft_entry_attrib.attribute_type == _ATTR_DATA:
            data_sizes.append(mft_entry_attrib.data_size)
            continue
        if mft_entry_attrib.attribute_type == _ATTR_FILE_NAME:
            path_hint = mft_entry.get_path_hint(mft_attrib_idx)
            macb_groups_ = list(
                macb_groups(
                    with_utc(mft_entry_attrib.modification_time),
                    with_utc(mft_entry_attrib.access_time),
                    with_utc(mft_entry_attrib.entry_modification_time),
                    with_utc(mft_entry_attrib.creation_time),
                )
            )
            record[_REC_FLAGS] = parse_file_name_flags(
                mft_entry_attrib.file_attribute_flags
            )
            if mft_entry_attrib.name_space != _NAMESPACE_DOS:
                record[_REC_PATH] = path_hint
    if not record[_REC_PATH]:
        return
    # yield standard records MACB grouped
    if data_sizes:
        record[_REC_SIZE] = data_sizes[0]
    for dtv, macb_string in macb_groups_:
        record[_REC_TIME] = to_iso_fmt(dtv)
        record[_REC_MACB] = macb_string
        yield record
    # process ADS if needed
    path_hint = record[_REC_PATH]
    for mft_entry_ads_idx in range(mft_entry.number_of_alternate_data_streams):
        try:
            mft_entry_ads = mft_entry.get_alternate_data_stream(
                mft_entry_ads_idx
            )
        except OSError:
            continue
        if not mft_entry_ads.name:
            continue
        record[_REC_PATH] = ':'.join([path_hint, mft_entry_ads.name])
        data_size_idx = mft_entry_ads_idx + 1
        record[_REC_SIZE] = (
            data_sizes[data_size_idx] if data_size_idx < len(data_sizes) else 0
        )
        # yield ADS records
        for dtv, macb_string in macb_groups_:
            record[_REC_TIME] = to_iso_fmt(dtv)
            record[_REC_MACB] = macb_string
            yield record


def _select_impl(directory: Path) -> PathIterator:
    pattern = ci_glob_pattern('$MFT')
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open('rb') as fobj:
        mft = mft_metadata_file()
        mft.open_file_object(fobj)
        for entry_idx in range(mft.number_of_file_entries):
            mft_entry = mft.get_file_entry(entry_idx)
            if (
                not mft_entry.is_empty()
                and mft_entry.base_record_file_reference == 0
            ):
                for record in _parse_mft_entry(mft_entry):
                    if not record:
                        continue
                    yield record


DISSECTOR = Dissector(
    slug='windows_mft',
    tags={Tag.WINDOWS},
    columns=[
        Column(_REC_TIME, DataType.STR),
        Column(_REC_MACB, DataType.STR),
        Column(_REC_PATH, DataType.STR),
        Column(_REC_SIZE, DataType.INT),
        Column(_REC_FLAGS, DataType.STR),
    ],
    description="NTFS MFT records",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
