"""python-libesedb wrapper"""

from pathlib import Path
from struct import unpack
from uuid import UUID

from edf_plasma_core.helper.datetime import from_ole_timestamp, to_iso_fmt
from pyesedb import check_file_signature as _check_file_signature
from pyesedb import column_types
from pyesedb import open_file_object as _open_file_object

_COLUMN_TYPE_PARSE_FUNC_MAPPING = {
    column_types.GUID: lambda r, i: str(UUID(bytes=r.get_value_data(i))),
    column_types.TEXT: lambda r, i: r.get_value_data_as_string(i),
    column_types.BOOLEAN: lambda r, i: r.get_value_data_as_boolean(i),
    column_types.DATE_TIME: lambda r, i: to_iso_fmt(
        from_ole_timestamp(
            unpack('d', r.get_value_data(i))[0] * 24 * 60 * 60 * 1000000
        )
    ),
    column_types.LARGE_TEXT: lambda r, i: r.get_value_data_as_string(i),
    column_types.BINARY_DATA: lambda r, i: r.get_value_data(i),
    column_types.LARGE_BINARY_DATA: lambda r, i: r.get_value_data(i),
    column_types.SUPER_LARGE_VALUE: lambda r, i: r.get_value_data(i),
    column_types.FLOAT_32BIT: lambda r, i: unpack('f', r.get_value_data(i))[0],
    column_types.DOUBLE_64BIT: lambda r, i: unpack('d', r.get_value_data(i))[
        0
    ],
    column_types.INTEGER_8BIT_UNSIGNED: lambda r, i: unpack(
        'B', r.get_value_data(i)
    )[0],
    column_types.INTEGER_16BIT_SIGNED: lambda r, i: unpack(
        'h', r.get_value_data(i)
    )[0],
    column_types.INTEGER_16BIT_UNSIGNED: lambda r, i: unpack(
        'H', r.get_value_data(i)
    )[0],
    column_types.INTEGER_32BIT_SIGNED: lambda r, i: unpack(
        'i', r.get_value_data(i)
    )[0],
    column_types.INTEGER_32BIT_UNSIGNED: lambda r, i: unpack(
        'I', r.get_value_data(i)
    )[0],
    column_types.INTEGER_64BIT_SIGNED: lambda r, i: unpack(
        'q', r.get_value_data(i)
    )[0],
}


def check_file_signature(filepath: Path) -> bool:
    """Determine if given file matches ese database signature"""
    try:
        return _check_file_signature(str(filepath))
    except OSError:
        return False


def open_file_object(ctx, fobj):
    """Open file object as ese database"""
    try:
        return _open_file_object(fobj)
    except OSError:
        ctx.register_error("open_file_object failed")
        return None


def iter_ese_tables(ctx, esedb):
    """Iterate over tables"""
    index = 0
    try:
        for index, table in enumerate(esedb.tables):
            yield table
    except OSError:
        ctx.register_error(f"iter_ese_tables failed at {index}")


def iter_ese_table_columns(ctx, table):
    """Iterate over table columns"""
    index = 0
    try:
        for index, column in enumerate(table.columns):
            yield column
    except OSError:
        ctx.register_error(f"iter_ese_table_columns failed at {index}")


def iter_ese_table_records(ctx, table):
    """Iterate over table records"""
    index = 0
    try:
        for index, record in enumerate(table.records):
            yield record
    except OSError:
        ctx.register_error(f"iter_ese_table_records failed at {index}")


def get_ese_table_name(ctx, table):
    """Get table name"""
    try:
        return table.name
    except OSError:
        ctx.register_error("get_ese_table_name failed")
        return None


def get_ese_column_name(ctx, column):
    """Get column name"""
    try:
        return column.name
    except OSError:
        ctx.register_error("get_ese_column_name failed")
        return None


def get_ese_column_type(ctx, column):
    """Get column type"""
    try:
        return column.type
    except OSError:
        ctx.register_error("get_ese_column_type failed")
        return None


def get_ese_column_parse(ctx, col_type):
    """Get column parsing function"""
    if col_type is None:
        return None
    parse = _COLUMN_TYPE_PARSE_FUNC_MAPPING.get(col_type)
    if parse is None:
        ctx.register_error("get_ese_column_parse failed")
    return parse


def get_ese_record_value(ctx, record, index, col_type):
    """Get record value for given index"""
    parse = get_ese_column_parse(ctx, col_type)
    if parse is None:
        return 'plasma:except:unsupported_type'
    try:
        return parse(record, index)
    except:
        ctx.register_error("get_ese_record_value failed to parse value")
        return 'plasma:except:parsing_failed'


def iter_ese_table_records_as_dicts(ctx, esedb, tablename):
    """Iterate over table records as dicts"""
    for table in iter_ese_tables(ctx, esedb):
        name = get_ese_table_name(ctx, table)
        if name != tablename:
            continue
        columns = [
            (
                get_ese_column_name(ctx, column),
                get_ese_column_type(ctx, column),
            )
            for column in iter_ese_table_columns(ctx, table)
        ]
        for record in iter_ese_table_records(ctx, table):
            yield {
                column[0]: get_ese_record_value(ctx, record, index, column[1])
                for index, column in enumerate(columns)
            }
        break
