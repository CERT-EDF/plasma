"""python-libscca wrapper"""

from pathlib import Path

from edf_plasma_core.helper.datetime import REF_WIN32, with_utc
from pyscca import check_file_signature as _check_file_signature
from pyscca import open_file_object as _open_file_object


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


def get_pf_last_run_times(ctx, prefetch):
    for index in range(8):
        try:
            dtv = prefetch.get_last_run_time(index)
        except OSError:
            ctx.register_error(f"get_last_run_times failed at {index}")
            break
        dtv = with_utc(dtv)
        if dtv == REF_WIN32:
            break
        yield dtv


def get_pf_exec_filename(ctx, prefetch):
    try:
        return prefetch.executable_filename
    except OSError:
        ctx.register_error("get_pf_exec_filename failed")
        return None


def get_pf_hash(ctx, prefetch):
    try:
        data = prefetch.prefetch_hash
    except OSError:
        ctx.register_error("get_pf_hash failed")
        return None
    return f'{data:08x}'.upper()


def get_pf_run_count(ctx, prefetch):
    try:
        return prefetch.run_count
    except OSError:
        ctx.register_error("get_pf_run_count failed")
        return None


def get_pf_filenames(ctx, prefetch):
    try:
        data = prefetch.filenames
    except OSError:
        ctx.register_error("get_pf_filenames failed")
        return None
    return ','.join(data)
