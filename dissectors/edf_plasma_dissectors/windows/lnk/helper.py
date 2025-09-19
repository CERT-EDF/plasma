"""python-liblnk wrapper"""

from pylnk import check_file_signature as pylnk_check_file_signature
from pylnk import check_file_signature_file_object, open_file_object


def check_file_signature(*args, **kwargs):
    try:
        return pylnk_check_file_signature(*args, **kwargs)
    except OSError:
        return False
