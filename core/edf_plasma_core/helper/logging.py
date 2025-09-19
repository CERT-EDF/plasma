"""Plasma Logging Helper"""

from logging import FileHandler, Formatter, basicConfig, getLogger
from os import getenv
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

DEBUG = int(getenv('PLASMA_DEBUG', '0'))
_LOGFILE = getenv('PLASMA_LOGFILE')
_HANDLERS = [RichHandler(console=Console(stderr=True), show_path=False)]
if _LOGFILE and Path(_LOGFILE).parent.is_dir():
    _FORMATTER = Formatter(
        fmt="%(asctime)s %(levelname)s (%(name)s): %(message)s",
        datefmt="[%Y-%m-%dT%H:%M:%S]",
    )
    _FILE_HANDLER = FileHandler(str(_LOGFILE), mode='w', encoding='utf-8')
    _FILE_HANDLER.setFormatter(_FORMATTER)
    _HANDLERS.append(_FILE_HANDLER)


basicConfig(
    level='DEBUG' if DEBUG else 'INFO',
    format="(%(name)s): %(message)s",
    datefmt="[%Y-%m-%dT%H:%M:%S]",
    handlers=_HANDLERS,
    force=True,
)


def get_logger(name: str, root: str = 'plasma'):
    """Retrieve logger for given name"""
    return getLogger('.'.join([root, name]))
