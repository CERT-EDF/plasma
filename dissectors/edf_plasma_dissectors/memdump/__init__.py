"""Memdump-related dissectors"""

from edf_plasma_core.helper.logging import get_logger

_LOGGER = get_logger('dissectors.memdump')

try:
    from . import linux, windows
except ModuleNotFoundError as exc:
    _LOGGER.warning("missing [memdump] dependency: '%s'", exc.name)
