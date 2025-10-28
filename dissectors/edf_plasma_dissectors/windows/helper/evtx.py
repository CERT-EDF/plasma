"""python-libevtx wrapper"""

from pathlib import Path

from edf_plasma_core.helper.importing import lazy_import

lazy_pyevtx = lazy_import('pyevtx')
PYEVTX_AVAILABLE = lazy_pyevtx is not None


def check_file_signature(filepath: Path) -> bool:
    """pyevtx.check_file_signature wrapper"""
    try:
        return lazy_pyevtx.check_file_signature(str(filepath))
    except OSError:
        return False


def open_file_object(ctx, fobj):
    """pyevtx.open_file_object wrapper"""
    try:
        return lazy_pyevtx.open_file_object(fobj)
    except OSError:
        ctx.register_error("open_file_object failed")
        return None


def iter_evtx_records(ctx, evtx):
    """Iterate over EVTX journal records"""
    index = 0
    try:
        for record in evtx.records:
            yield record
            index += 1
    except OSError:
        ctx.register_error(f"iter_evtx_records failed at {index}")


def get_record_as_xml(ctx, record):
    """Retrieve XML representation of an EVTX record"""
    try:
        return record.xml_string
    except OSError:
        ctx.register_error("get_record_as_xml failed")
        return None


def get_record_creation_time(ctx, record):
    """Retrieve EVTX record creation time"""
    try:
        return record.creation_time
    except OSError:
        ctx.register_error("get_record_creation_time failed")
        return None
