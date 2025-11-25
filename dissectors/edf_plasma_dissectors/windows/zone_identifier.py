"""Windows Zone.Identifier artifact dissector"""

from configparser import ConfigParser
from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.glob import ci_glob_pattern
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    pattern = ci_glob_pattern('*%3AZone.Identifier')
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    parser = ConfigParser()
    if not parser.read(ctx.filepath):
        ctx.register_error(f"failed to parse {ctx.filepath}")
        return
    yield {
        'zone_id': parser.get('ZoneTransfer', 'ZoneId', fallback=None),
        'host_url': parser.get('ZoneTransfer', 'HostUrl', fallback=None),
        'referrer_url': parser.get(
            'ZoneTransfer', 'ReferrerUrl', fallback=None
        ),
    }


DISSECTOR = Dissector(
    slug='windows_zone_identifier',
    tags={Tag.WINDOWS},
    columns=[
        Column('zone_id', DataType.STR),
        Column('host_url', DataType.STR),
        Column('referrer_url', DataType.STR),
    ],
    description="Zone.Identifier ADS",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
