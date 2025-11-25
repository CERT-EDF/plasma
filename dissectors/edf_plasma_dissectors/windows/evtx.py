"""Windows EVTX artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import to_iso_fmt, with_utc
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator
from edf_plasma_core.helper.xml import check_xml_parser_safety

from .helper.evtx import (
    check_file_signature,
    get_record_as_xml,
    get_record_creation_time,
    iter_evtx_records,
    open_file_object,
)
from .xml.evtx import Event

_LOGGER = get_logger('dissectors.windows.evtx')


def _select_impl(directory: Path) -> PathIterator:
    if not check_xml_parser_safety():
        _LOGGER.error("XML parser is not safe!")
        return
    pattern = ci_glob_pattern('*.evtx')
    for filepath in select(directory, pattern):
        if not check_file_signature(filepath):
            _LOGGER.warning("signature check failed for %s", filepath)
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open('rb') as fobj:
        evtx = open_file_object(ctx, fobj)
        if evtx is None:
            return
        for record in iter_evtx_records(ctx, evtx):
            xml = get_record_as_xml(ctx, record)
            if xml is None:
                continue
            event = Event.from_string(record.xml_string)
            if event is None:
                ctx.register_error("Event.from_string failed")
                continue
            ctime = get_record_creation_time(ctx, record)
            if ctime is None:
                continue
            yield {
                'evt_time': to_iso_fmt(with_utc(ctime)),
                'evt_channel': event.system.channel,
                'evt_provider': event.system.provider,
                'evt_computer': event.system.computer,
                'evt_id': event.system.event_id,
                'evt_data': event.data,
            }


DISSECTOR = Dissector(
    slug='windows_evtx',
    tags={Tag.WINDOWS},
    columns=[
        Column('evt_time', DataType.STR),
        Column('evt_channel', DataType.STR),
        Column('evt_provider', DataType.STR),
        Column('evt_computer', DataType.STR),
        Column('evt_id', DataType.INT),
        Column('evt_data', DataType.STR),
    ],
    description="Events from EVTX files",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
