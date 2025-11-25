"""Sysdiagnose shutdown artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator


def _select_impl(directory: Path) -> PathIterator:
    pattern = 'remotectl_dumpstate.txt'
    yield from select(directory, pattern)


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    with ctx.filepath.open(encoding='utf-8') as fobj:
        device = {}
        devices = []
        for line in fobj:
            line = line.strip()
            if not line:
                continue
            if line.startswith('UUID'):
                device = {}
                devices.append(device)
                device['uuid'] = line.split(': ', 1)[-1].lower()
            if line.startswith('BuildVersion'):
                device['build_version'] = line.split(' => ', 1)[-1]
            if line.startswith('OSVersion'):
                device['os_version'] = line.split(' => ', 1)[-1]
            if line.startswith('ProductName'):
                device['product_name'] = line.split(' => ', 1)[-1]
            if line.startswith('ProductType'):
                device['product_type'] = line.split(' => ', 1)[-1]
            if line.startswith('SerialNumber'):
                device['serial_number'] = line.split(' => ', 1)[-1]
            if line.startswith('DeviceClass'):
                device['device_class'] = line.split(' => ', 1)[-1]
            if line.startswith('CPUArchitecture'):
                device['cpu_arch'] = line.split(' => ', 1)[-1]
        for device in devices:
            record = {
                'uuid': '',
                'build_version': '',
                'os_version': '',
                'product_name': '',
                'product_type': '',
                'serial_number': '',
                'device_class': '',
                'cpu_arch': '',
            }
            record.update(device)
            yield record


DISSECTOR = Dissector(
    slug='ios_sysdiag_remotectl',
    tags={Tag.SYSDIAG, Tag.IOS},
    columns=[
        Column('uuid', DataType.STR),
        Column('build_version', DataType.STR),
        Column('os_version', DataType.STR),
        Column('product_name', DataType.STR),
        Column('product_type', DataType.STR),
        Column('serial_number', DataType.STR),
        Column('device_class', DataType.STR),
        Column('cpu_arch', DataType.STR),
    ],
    description="iOS sysdiagnose remotectl output",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
