"""python-libregf wrapper"""

from enum import Enum
from pathlib import Path

from edf_plasma_core.helper.importing import lazy_import

lazy_pyregf = lazy_import('pyregf')
PYREGF_AVAILABLE = lazy_pyregf is not None


class ValueType(Enum):
    """Registry value type"""

    REG_NONE = 0x00000000
    REG_SZ = 0x00000001
    REG_EXPAND_SZ = 0x00000002
    REG_BINARY = 0x00000003
    REG_DWORD = 0x00000004
    REG_DWORD_LITTLE_ENDIAN = 0x00000004
    REG_DWORD_BIG_ENDIAN = 0x00000005
    REG_LINK = 0x00000006
    REG_MULTI_SZ = 0x00000007
    REG_RESOURCE_LIST = 0x00000008
    REG_QWORD = 0x0000000B
    REG_QWORD_LITTLE_ENDIAN = 0x0000000B
    REG_INVALID_TYPE = 0xFFFFFFFF


def check_file_signature(filepath: Path) -> bool:
    try:
        return lazy_pyregf.check_file_signature(str(filepath))
    except OSError:
        return False


def open_file_object(ctx, fobj):
    try:
        return lazy_pyregf.open_file_object(fobj)
    except OSError:
        ctx.register_error("open_file_object failed")
        return None


def get_root_key(ctx, registry):
    try:
        return registry.root_key
    except OSError:
        ctx.register_error("get_root_key failed")
        return None


def get_key_name(ctx, key):
    try:
        return key.name
    except OSError:
        ctx.register_error("get_key_name failed")
        return None


def get_key_last_written_time(ctx, key):
    try:
        return key.last_written_time
    except OSError:
        ctx.register_error("get_key_last_written_time failed")
        return None


def iter_key_values(ctx, key):
    index = 0
    try:
        for value in key.values:
            yield value
            index += 1
    except OSError:
        ctx.register_error(f"iter_key_values failed at {index}")
        return


def iter_key_sub_keys(ctx, key):
    index = 0
    try:
        for sub_key in key.sub_keys:
            yield sub_key
            index += 1
    except OSError:
        ctx.register_error(f"iter_key_sub_keys failed at {index}")
        return


def get_value_name(ctx, value):
    try:
        return value.name or 'default'
    except OSError:
        ctx.register_error("get_value_name failed")
        return None


def get_value_type(ctx, value) -> ValueType:
    try:
        data = value.type
    except OSError:
        ctx.register_error("get_value_type failed")
        return None
    try:
        return ValueType(data)
    except ValueError:
        return ValueType.REG_INVALID_TYPE


def get_value_as_string(ctx, value):
    try:
        return value.get_data_as_string()
    except OSError:
        ctx.register_error("value_as_string failed")
        return 'plasma:except:value_as_string_failed'


def get_value_as_multi_string(ctx, value):
    try:
        data = value.get_data_as_multi_string()
    except OSError:
        ctx.register_error("value_as_multi_string failed")
        return 'plasma:except:value_as_multi_string_failed'
    return ','.join(data)


def get_value_as_integer(ctx, value):
    try:
        return str(value.get_data_as_integer())
    except OSError:
        ctx.register_error("value_as_integer failed")
        return 'plasma:except:value_as_integer_failed'


def get_value_as_bytes(_ctx, value):
    vdata = value.get_data()
    if vdata is None:
        return 'plasma:empty'
    if len(vdata) > 64:
        return f'plasma:too_many_bytes:{len(vdata)}'
    return vdata.hex()
