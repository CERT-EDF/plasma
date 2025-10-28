"""Plasma main program"""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from sys import exit as sys_exit
from sys import modules

# load dissectors
import edf_plasma_dissectors as _
from edf_plasma_core.helper.logging import get_logger

from .__version__ import version
from .command import Format, setup_commands

_LOGGER = get_logger('cli')


def _parse_args():
    _LOGGER.info("Plasma v%s", version)
    parser = ArgumentParser(description=f"Plasma v{version}")
    parser.add_argument(
        '--plugin-directory',
        '-p',
        type=Path,
        help="Plugin directory to register extra dissectors",
    )
    parser.add_argument(
        '--format',
        '-f',
        choices=[fmt.value for fmt in Format],
        default=Format.RICH.value,
        help="Output format",
    )
    cmd = parser.add_subparsers(dest='cmd')
    cmd.required = True
    setup_commands(cmd)
    args = parser.parse_args()
    args.format = Format(args.format)
    return args


def _import_from_file(plugin: Path):
    spec = spec_from_file_location(plugin.stem, plugin)
    module = module_from_spec(spec)
    modules[plugin.stem] = module
    spec.loader.exec_module(module)


def _import_from_directory(plugin_directory: Path):
    if not plugin_directory:
        return
    if not plugin_directory.is_dir():
        return
    for plugin in plugin_directory.glob('*.py'):
        if not plugin.is_file():
            continue
        _import_from_file(plugin)


def app():
    """Application entrypoint"""
    args = _parse_args()
    _import_from_directory(args.plugin_directory)
    exit_code = 0
    try:
        args.func(args)
    except:
        _LOGGER.exception("exception caught in main handler!")
        exit_code = 1
    sys_exit(exit_code)
