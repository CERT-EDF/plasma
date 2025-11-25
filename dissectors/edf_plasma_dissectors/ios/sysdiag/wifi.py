"""Sysdiagnose disk artifact dissector"""

from pathlib import Path
from plistlib import load

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import to_iso_fmt, with_utc
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'WiFi/com.apple.wifi-private-mac-networks.plist'
    yield from select(directory, pattern)


def _get_iso_date(ap_info, member) -> str:
    dtv = ap_info.get(member)
    if not dtv:
        return ''
    return to_iso_fmt(with_utc(dtv))


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open('rb') as fobj:
        data = load(fobj)
        for ap_info in data['List of scanned networks with private mac']:
            yield {
                'ap_ssid': ap_info.get('SSID_STR', ''),
                'ap_bssid': ap_info.get('BSSID', ''),
                'ap_open': ap_info.get('IsOpenNetwork', False),
                'ap_captive': ap_info.get('CaptiveNetwork', False),
                'ap_added': _get_iso_date(ap_info, 'addedAt'),
                'ap_last_joined': _get_iso_date(ap_info, 'lastJoined'),
                'ap_first_joined': _get_iso_date(
                    ap_info, 'FirstJoinWithNewMacTimestamp'
                ),
            }


DISSECTOR = Dissector(
    slug='ios_sysdiag_wifi',
    tags={Tag.SYSDIAG, Tag.IOS},
    columns=[
        Column('ap_ssid', DataType.STR),
        Column('ap_bssid', DataType.STR),
        Column('ap_open', DataType.BOOL),
        Column('ap_captive', DataType.BOOL),
        Column('ap_added', DataType.STR),
        Column('ap_last_joined', DataType.STR),
        Column('ap_first_joined', DataType.STR),
    ],
    description="iOS sysdiagnose disk output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
