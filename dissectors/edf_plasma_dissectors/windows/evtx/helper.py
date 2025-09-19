"""python-libevtx wrapper"""

from pathlib import Path

from pyevtx import check_file_signature as _check_file_signature
from pyevtx import open_file_object as _open_file_object


def check_file_signature(filepath: Path) -> bool:
    try:
        return _check_file_signature(str(filepath))
    except OSError:
        return False


def open_file_object(ctx, fobj):
    try:
        return _open_file_object(fobj)
    except OSError:
        ctx.register_error("open_file_object failed")
        return None


def iter_evtx_records(ctx, evtx):
    index = 0
    try:
        for record in evtx.records:
            yield record
            index += 1
    except OSError:
        ctx.register_error(f"iter_evtx_records failed at {index}")
        return


def get_record_as_xml(ctx, record):
    try:
        return record.xml_string
    except OSError:
        ctx.register_error("get_record_as_xml failed")
        return None


def get_record_creation_time(ctx, record):
    try:
        return record.creation_time
    except OSError:
        ctx.register_error("get_record_creation_time failed")
        return None
