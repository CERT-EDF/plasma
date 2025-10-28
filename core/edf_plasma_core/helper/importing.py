"""Import helpers"""

from importlib.util import (
    LazyLoader,
    find_spec,
    module_from_spec,
    spec_from_file_location,
)
from pathlib import Path
from sys import modules
from typing import Any

from .logging import get_logger

_LOGGER = get_logger('core.helper.importing')


def _exec_module(name, spec):
    module = module_from_spec(spec)
    modules[name] = module
    spec.loader.exec_module(module)
    return module


def lazy_import(name: str) -> Any:
    """Create a lazy imported module"""
    if name in modules:
        return modules[name]
    try:
        spec = find_spec(name)
    except ModuleNotFoundError:
        _LOGGER.warning("module '%s' is missing", name)
        return None
    if spec is None:
        _LOGGER.warning("module '%s' is missing", name)
        return None
    loader = LazyLoader(spec.loader)
    spec.loader = loader
    return _exec_module(name, spec)


def import_from_file(filepath: Path) -> Any:
    """Import python module from filepath"""
    if not filepath.is_file():
        _LOGGER.warning("file not found, cannot import '%s'", filepath)
        return None
    name = filepath.stem
    if name in modules:
        return modules[name]
    spec = spec_from_file_location(name, filepath)
    return _exec_module(name, spec)
