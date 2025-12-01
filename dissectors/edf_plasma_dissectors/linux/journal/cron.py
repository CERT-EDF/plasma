"""Journal CRON Dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import to_iso_fmt, with_utc
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from .helper import journal_reader, select_journal_impl


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    reader = journal_reader(ctx)
    if reader is None:
        return
    reader.add_match(SYSLOG_FACILITY=15)
    for dct in reader:
        yield {
            'journal_time': to_iso_fmt(with_utc(dct['__REALTIME_TIMESTAMP'])),
            'journal_hostname': dct['_HOSTNAME'],
            'journal_facility': dct['SYSLOG_FACILITY'],
            'journal_identifier': dct['SYSLOG_IDENTIFIER'],
            'journal_message': dct['MESSAGE'],
        }


DISSECTOR = Dissector(
    slug='linux_journal_cron',
    tags={Tag.LINUX},
    columns=[
        Column('journal_time', DataType.STR),
        Column('journal_hostname', DataType.STR),
        Column('journal_facility', DataType.INT),
        Column('journal_identifier', DataType.STR),
        Column('journal_message', DataType.STR),
    ],
    description="Linux cron events from systemd journal",
    select_impl=select_journal_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
