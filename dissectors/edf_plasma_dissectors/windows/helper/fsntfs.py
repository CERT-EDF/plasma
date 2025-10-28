"""python-libfsntfs wrapper"""

from edf_plasma_core.helper.importing import lazy_import

lazy_pyfsntfs = lazy_import('pyfsntfs')
PYFSNTFS_AVAILABLE = lazy_pyfsntfs is not None


def mft_metadata_file():
    """pyfsntfs.mft_metadata_file wrapper"""
    return lazy_pyfsntfs.mft_metadata_file()
