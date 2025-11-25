"""Journal Auth Dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import with_utc
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

from .helper import journal_reader


def _select_impl(directory: Path) -> PathIterator:
    pattern = '*.journal'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    reader = journal_reader(ctx)
    if reader is None:
        return
    reader.add_match("SYSLOG_FACILITY=10", "SYSLOG_FACILITY=4")
    for dct in reader:
        yield {
            'journal_time': with_utc(dct['__REALTIME_TIMESTAMP']),
            'journal_hostname': dct['_HOSTNAME'],
            'journal_facility': dct['SYSLOG_FACILITY'],
            'journal_identifier': dct['SYSLOG_IDENTIFIER'],
            'journal_message': dct['MESSAGE'],
            'journal_exe': dct.get('_EXE', ''),
            'journal_cmdline': dct.get('_CMDLINE', ''),
        }


DISSECTOR = Dissector(
    slug='linux_journal_auth',
    tags={Tag.LINUX},
    columns=[
        Column('journal_time', DataType.STR),
        Column('journal_hostname', DataType.STR),
        Column('journal_facility', DataType.INT),
        Column('journal_identifier', DataType.STR),
        Column('journal_message', DataType.STR),
        Column('journal_exe', DataType.STR),
        Column('journal_cmdline', DataType.STR),
    ],
    description="auth events from systemd journal",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
