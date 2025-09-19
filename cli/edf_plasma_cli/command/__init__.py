"""Command module"""

from .abc import Format
from .dissect import setup_command as setup_dissect_command
from .list import setup_command as setup_list_command

_COMMANDS = (
    setup_dissect_command,
    setup_list_command,
)


def setup_commands(cmd):
    """Setup commands"""
    for setup_command in _COMMANDS:
        setup_command(cmd)
