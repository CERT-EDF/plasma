"""MVT iOS AnalyticsAdDaily artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.json import read_json
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'os_analytics_ad_daily.json'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    records = read_json(ctx.filepath)
    if records is None:
        ctx.register_error(f"failed to load JSON data from: {ctx.filepath}")
        return
    for record in records:
        if not isinstance(record, dict):
            ctx.register_error(f"unsupported format: {ctx.filepath}")
            return
        wifi_in = record['wifi_in'] or -1
        wifi_out = record['wifi_out'] or -1
        wwan_in = record['wwan_in'] or -1
        wwan_out = record['wwan_out'] or -1
        yield {
            'aad_ts': record['ts'],
            'aad_package': record['package'],
            'aad_wifi_in': int(wifi_in),
            'aad_wifi_out': int(wifi_out),
            'aad_wwan_in': int(wwan_in),
            'aad_wwan_out': int(wwan_out),
        }


DISSECTOR = Dissector(
    slug='ios_mvt_analytics_ad_daily',
    tags={Tag.MVT, Tag.IOS},
    columns=[
        Column('aad_ts', DataType.STR),
        Column('aad_package', DataType.STR),
        Column('aad_wifi_in', DataType.INT),
        Column('aad_wifi_out', DataType.INT),
        Column('aad_wwan_in', DataType.INT),
        Column('aad_wwan_out', DataType.INT),
    ],
    description="MVT iOS os analytics ad daily output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
