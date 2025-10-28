"""python-libolecf wrapper"""

from pathlib import Path

from edf_plasma_core.helper.importing import lazy_import

lazy_pyolecf = lazy_import('pyolecf')
PYOLECF_AVAILABLE = lazy_pyolecf is not None


def check_file_signature(filepath: Path) -> bool:
    """pyevtx.check_file_signature wrapper"""
    try:
        return lazy_pyolecf.check_file_signature(str(filepath))
    except OSError:
        return False


def open_file_object(ctx, fobj):
    """pyevtx.open_file_object wrapper"""
    try:
        return lazy_pyolecf.open_file_object(fobj)
    except OSError:
        ctx.register_error("open_file_object failed")
        return None
