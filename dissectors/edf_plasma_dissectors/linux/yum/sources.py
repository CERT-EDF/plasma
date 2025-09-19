"""YUM Sources Dissector"""

from configparser import ConfigParser
from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_GLOB_PATTERN = 'yum.repos.d/*.repo'


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob(_GLOB_PATTERN):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    configparser = ConfigParser()
    configparser.read(ctx.filepath)
    for section in configparser.sections():
        yield {
            'src_section': section,
            'src_name': configparser.get(section, 'name', fallback=None),
            'src_baseurl': configparser.get(section, 'baseurl', fallback=None),
            'src_enabled': configparser.get(section, 'enabled', fallback=None),
            'src_gpgcheck': configparser.get(
                section, 'gpgcheck', fallback=None
            ),
            'src_gpgkey': configparser.get(section, 'gpgkey', fallback=None),
            'src_proxy': configparser.get(section, 'proxy', fallback=None),
        }


DISSECTOR = Dissector(
    slug='linux_yum_sources',
    tags={Tag.LINUX},
    columns=[
        Column('src_section', DataType.STR),
        Column('src_name', DataType.STR),
        Column('src_baseurl', DataType.STR),
        Column('src_enabled', DataType.STR),
        Column('src_gpgcheck', DataType.STR),
        Column('src_gpgkey', DataType.STR),
        Column('src_proxy', DataType.STR),
    ],
    description="yum sources",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
