"""Windows registry artifact dissector"""

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
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

from .helper.regf import (
    ValueType,
    check_file_signature,
    get_key_last_written_time,
    get_key_name,
    get_root_key,
    get_value_as_bytes,
    get_value_as_integer,
    get_value_as_multi_string,
    get_value_as_string,
    get_value_name,
    get_value_type,
    iter_key_sub_keys,
    iter_key_values,
    open_file_object,
)

_LOGGER = get_logger('dissectors.windows.registry')
_VALUE_TYPE_PARSER = {
    ValueType.REG_SZ: get_value_as_string,
    ValueType.REG_EXPAND_SZ: get_value_as_string,
    ValueType.REG_MULTI_SZ: get_value_as_multi_string,
    ValueType.REG_DWORD: get_value_as_integer,
}


def _parse_value(ctx: DissectionContext, value) -> tuple[str, str, str]:
    vname = get_value_name(ctx, value)
    if vname is None:
        return None, None, None
    vtype = get_value_type(ctx, value)
    if vtype == ValueType.REG_INVALID_TYPE:
        return vname, vtype.name, ''
    parse_func = _VALUE_TYPE_PARSER.get(vtype, get_value_as_bytes)
    return vname, vtype.name, parse_func(ctx, value)


def _scan_registry(ctx: DissectionContext, key, keypath=None):
    if not keypath:
        keypath = []
    key_name = get_key_name(ctx, key)
    if key_name is None:
        return
    keypath.append(key_name)
    reg_key = '\\'.join(keypath)
    for value in iter_key_values(ctx, key):
        reg_vname, reg_vtype, reg_vdata = _parse_value(ctx, value)
        if reg_vname is None:
            continue
        lwt = get_key_last_written_time(ctx, key)
        if lwt is None:
            continue
        yield {
            'reg_time': to_iso_fmt(with_utc(lwt)),
            'reg_key': reg_key,
            'reg_vname': reg_vname,
            'reg_vtype': reg_vtype,
            'reg_vdata': reg_vdata,
        }
    for subkey in iter_key_sub_keys(ctx, key):
        yield from _scan_registry(ctx, subkey, keypath)
    keypath.pop()


def _registry_records(ctx: DissectionContext):
    with ctx.filepath.open('rb') as fobj:
        registry = open_file_object(ctx, fobj)
        if registry is None:
            return
        root_key = get_root_key(ctx, registry)
        if root_key is None:
            return
        yield from _scan_registry(ctx, root_key)


_REGISTRIES = (
    ci_glob_pattern('SYSTEM'),
    ci_glob_pattern('SAM'),
    ci_glob_pattern('SECURITY'),
    ci_glob_pattern('SOFTWARE'),
    ci_glob_pattern('DEFAULT'),
    ci_glob_pattern('NTUSER.DAT'),
    ci_glob_pattern('Amcache.hve'),
)


def _select_impl(directory: Path) -> PathIterator:
    for filename in _REGISTRIES:
        for filepath in directory.rglob(filename):
            if not filepath.is_file():
                continue
            if not check_file_signature(filepath):
                _LOGGER.warning(
                    "registry signature check failed: %s", filepath
                )
                continue
            yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    yield from _registry_records(ctx)


DISSECTOR = Dissector(
    slug='windows_registry',
    tags={Tag.WINDOWS},
    columns=[
        Column('reg_time', DataType.STR),
        Column('reg_key', DataType.STR),
        Column('reg_vname', DataType.STR),
        Column('reg_vtype', DataType.STR),
        Column('reg_vdata', DataType.STR),
    ],
    description="Registry hives",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
