"""Windows IIS journal artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_PATTERN = ci_glob_pattern('u_ex*.log')
_FIELD_MAPPING = {
    'date': 'date',
    'time': 'time',
    'c-ip': 'c_ip',
    'cs-username': 'cs_user',
    's-sitename': 's_site',
    's-computername': 's_computer',
    's-ip': 's_ip',
    's-port': 's_port',
    'cs-method': 'cs_method',
    'cs-uri-stem': 'cs_path',
    'cs-uri-query': 'cs_query',
    'sc-status': 'sc_status',
    'sc-win32-status': 'sc_win_status',
    'sc-bytes': 'sc_bytes',
    'cs-bytes': 'cs_bytes',
    'time-taken': 'duration',
    'cs-version': 'cs_version',
    'cs-host': 'cs_host',
    'cs(User-Agent)': 'cs_ua',
    'cs(Cookie)': 'cs_cookie',
    'cs(Referer)': 'cs_refer',
    'sc-substatus': 'sc_substatus',
}


def _str_val(val):
    return '' if val == '-' else val


def _int_val(val):
    return -1 if val == '-' else int(val)


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob(_PATTERN):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open('r') as fobj:
        # parse header
        fields = []
        for line in fobj:
            line = line.rstrip()
            if line.startswith('#Fields: '):
                line = line.split(' ', 1)[-1]
                fields = [_FIELD_MAPPING[field] for field in line.split(' ')]
                break
        if not fields:
            ctx.register_error("failed to extract fields from journal header")
            return
        # process lines
        for line in fobj:
            line = line.rstrip()
            if line.startswith('#'):
                continue
            entry = dict(zip(fields, line.split(' ')))
            date = entry.pop('date')
            time = entry.pop('time')
            yield {
                'time': f'{date}T{time}Z',
                'c_ip': _str_val(entry.get('c_ip', '-')),
                'cs_user': _str_val(entry.get('cs_user', '-')),
                's_site': _str_val(entry.get('s_site', '-')),
                's_computer': _str_val(entry.get('s_computer', '-')),
                's_ip': _str_val(entry.get('s_ip', '-')),
                's_port': _int_val(entry.get('s_port', '-')),
                'cs_method': _str_val(entry.get('cs_method', '-')),
                'cs_path': _str_val(entry.get('cs_path', '-')),
                'cs_query': _str_val(entry.get('cs_query', '-')),
                'sc_status': _int_val(entry.get('sc_status', '-')),
                'sc_bytes': _int_val(entry.get('sc_bytes', '-')),
                'cs_bytes': _int_val(entry.get('cs_bytes', '-')),
                'duration': _int_val(entry.get('duration', '-')),
                'cs_ua': _str_val(entry.get('cs_ua', '-')),
                'cs_refer': _str_val(entry.get('cs_refer', '-')),
            }


DISSECTOR = Dissector(
    slug='windows_iis',
    tags={Tag.WINDOWS},
    columns=[
        Column('time', DataType.STR),
        Column('c_ip', DataType.STR),
        Column('cs_user', DataType.STR),
        Column('s_site', DataType.STR),
        Column('s_computer', DataType.STR),
        Column('s_ip', DataType.STR),
        Column('s_port', DataType.INT),
        Column('cs_method', DataType.STR),
        Column('cs_path', DataType.STR),
        Column('cs_query', DataType.STR),
        Column('sc_status', DataType.INT),
        Column('sc_bytes', DataType.INT),
        Column('cs_bytes', DataType.INT),
        Column('duration', DataType.INT),
        Column('cs_ua', DataType.STR),
        Column('cs_refer', DataType.STR),
    ],
    description="IIS journal entries",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
