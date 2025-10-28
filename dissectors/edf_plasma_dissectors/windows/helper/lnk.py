"""python-liblnk wrapper"""

from pathlib import Path

from edf_plasma_core.helper.importing import lazy_import

lazy_pylnk = lazy_import('pylnk')
PYLNK_AVAILABLE = lazy_pylnk is not None


def check_file_signature(filepath: Path):
    """pylnk.check_file_signature wrapper"""
    try:
        return lazy_pylnk.check_file_signature(str(filepath))
    except OSError:
        return False


def check_file_signature_file_object(fobj):
    """pylnk.check_file_signature_file_obj wrapper"""
    try:
        return lazy_pylnk.check_file_signature_file_object(fobj)
    except OSError:
        return False


def open_file_object(fobj):
    """pylnk.open_file_object wrapper"""
    try:
        return lazy_pylnk.open_file_object(fobj)
    except OSError:
        return None
