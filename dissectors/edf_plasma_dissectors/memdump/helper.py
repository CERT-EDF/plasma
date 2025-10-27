"""Memory dissectors helper"""

from collections.abc import Iterator
from datetime import datetime
from functools import partial
from os import getenv
from pathlib import Path
from threading import Event, Lock

from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.typing import PathIterator
from volatility3 import plugins, symbols
from volatility3.framework import (
    automagic,
    constants,
    contexts,
    clear_cache,
    exceptions,
    import_files,
    interfaces,
    list_plugins,
    require_interface_version,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.plugins import construct_plugin
from volatility3.framework.renderers import (
    NotApplicableValue,
    UnparsableValue,
    format_hints,
)


_LOGGER = get_logger('dissectors.memory.helper')
_SETUP_LOCK = Lock()
_SETUP_FLAG = Event()


_MEMDUMP_MAGICS = (
    b'LMVA',
    b'EGAP',
    b'\x7FELF',
    b'LiME',
    b'QEVM',
    b'\xd0\xbe\xd2\xbe',
    b'\xd1\xba\xd1\xba',
    b'\xd2\xbe\xd2\xbe',
    b'\xd3\xbe\xd3\xbe',
)


def is_memdump(filepath: Path):
    """Determine if filepath is a PCAP"""
    with filepath.open('rb') as fobj:
        return fobj.read(4) in _MEMDUMP_MAGICS


def select_memdump_impl(directory: Path) -> PathIterator:
    """Select memdump files in directory"""
    for filepath in directory.rglob('*'):
        if not is_memdump(filepath):
            continue
        yield filepath


def _hex_bytes_as_text(value: bytes, width: int = 16) -> str:
    """Display value in hex/ascii dump format"""
    if not isinstance(value, bytes):
        raise TypeError(f"hex_bytes_as_text takes bytes not: {type(value)}")
    printables = ""
    output = "\n"
    for count, byte in enumerate(value):
        output += f"{byte:02x} "
        char = chr(byte)
        printables += char if 0x20 <= byte <= 0x7E else "."
        if count % width == width - 1:
            output += printables
            if count < len(value) - 1:
                output += "\n"
            printables = ""
    if printables:
        padding = width - len(printables)
        output += "   " * padding
        output += printables
        output += " " * padding
    return output


def _multitypedata_as_text(value: format_hints.MultiTypeData) -> str:
    """Display bytes characters where possible, otherwise display hex data"""
    if value.show_hex:
        return _hex_bytes_as_text(value)
    string_representation = str(
        value, encoding=value.encoding, errors='replace'
    )
    if value.split_nulls and (
        (len(value) / 2 - 1) <= len(string_representation) <= (len(value) / 2)
    ):
        return "\n".join(string_representation.split('\x00'))
    if (
        len(string_representation) - 1
        <= len(string_representation.split('\x00')[0])
        <= len(string_representation)
    ):
        return string_representation.split('\x00')[0]
    return _hex_bytes_as_text(value)


def _invalid(val):
    return isinstance(val, (UnparsableValue, NotApplicableValue))


_RENDERER_STRATEGY = {
    format_hints.Bin: lambda val: None if _invalid(val) else f'0b{val:b}',
    format_hints.Hex: lambda val: None if _invalid(val) else f'0x{val:x}',
    format_hints.HexBytes: _hex_bytes_as_text,
    format_hints.MultiTypeData: _multitypedata_as_text,
    datetime: lambda val: None if _invalid(val) else val.isoformat(),
}


def _visitor(node: interfaces.renderers.TreeNode, accumulator, columns):
    row = {'TreeDepth': str(max(0, node.path_depth - 1))}
    for column_index, column in enumerate(columns):
        renderer = _RENDERER_STRATEGY.get(column.type, lambda val: f'{val}')
        row[f'{column.name}'] = renderer(node.values[column_index])
    accumulator.append(row)
    return accumulator


def _log_unsatisfied_exception(exc):
    """Provide useful feedback if an exception occurs during requirement fulfillment."""
    translation_failed = False
    symbols_failed = False
    for config_path in exc.unsatisfied:
        translation_failed = translation_failed or isinstance(
            exc.unsatisfied[config_path],
            requirements.TranslationLayerRequirement,
        )
        symbols_failed = symbols_failed or isinstance(
            exc.unsatisfied[config_path],
            requirements.SymbolTableRequirement,
        )
        _LOGGER.error(
            "unsatisfied requirement %s: %s",
            config_path,
            exc.unsatisfied[config_path].description,
        )

    if translation_failed:
        _LOGGER.error(
            "\nA translation layer requirement was not fulfilled.  Please verify that:\n"
            "\tA file was provided to create this layer (by -f, --single-location or by config)\n"
            "\tThe file exists and is readable\n"
            "\tThe file is a valid memory image and was acquired cleanly"
        )
    if symbols_failed:
        _LOGGER.error(
            "\nA symbol table requirement was not fulfilled.  Please verify that:\n"
            "\tThe associated translation layer requirement was fulfilled\n"
            "\tYou have the correct symbol file for the requirement\n"
            "\tThe symbol file is under the correct directory or zip file\n"
            "\tThe symbol file is named appropriately or contains the correct banner\n"
        )


def _log_exception(exc):
    """Provide useful feedback if an exception occurs during a run of a plugin."""
    _LOGGER.exception(
        "exception raised while plugin was processing the memory image!"
    )

    file_a_bug_msg = f"Please re-run with -vvv and file a bug with the output at {constants.BUG_URL}"

    if isinstance(exc, exceptions.InvalidAddressException):
        general = "Volatility was unable to read a requested page:"
        if isinstance(exc, exceptions.SwappedInvalidAddressException):
            detail = f"Swap error {hex(exc.invalid_address)} in layer {exc.layer_name} ({exc})"
            caused_by = [
                "No suitable swap file having been provided (locate and provide the correct swap file)",
                "An intentionally invalid page (operating system protection)",
            ]
        elif isinstance(exc, exceptions.PagedInvalidAddressException):
            detail = f"Page error {hex(exc.invalid_address)} in layer {exc.layer_name} ({exc})"
            caused_by = [
                "Memory smear during acquisition (try re-acquiring if possible)",
                "An intentionally invalid page lookup (operating system protection)",
                "A bug in the plugin/volatility3 (re-run with -vvv and file a bug)",
            ]
        else:
            detail = (
                f"{hex(exc.invalid_address)} in layer {exc.layer_name} ({exc})"
            )
            caused_by = [
                "The base memory file being incomplete (try re-acquiring if possible)",
                "Memory smear during acquisition (try re-acquiring if possible)",
                "An intentionally invalid page lookup (operating system protection)",
                "A bug in the plugin/volatility3 (re-run with -vvv and file a bug)",
            ]
    elif isinstance(exc, exceptions.SymbolError):
        general = "Volatility experienced a symbol-related issue:"
        detail = f"{exc.table_name}{constants.BANG}{exc.symbol_name}: {exc}"
        caused_by = [
            "An invalid symbol table",
            "A plugin requesting a bad symbol",
            "A plugin requesting a symbol from the wrong table",
        ]
    elif isinstance(exc, exceptions.SymbolSpaceError):
        general = "Volatility experienced an issue related to a symbol table:"
        detail = f"{exc}"
        caused_by = [
            "An invalid symbol table",
            "A plugin requesting a bad symbol",
            "A plugin requesting a symbol from the wrong table",
        ]
    elif isinstance(exc, exceptions.LayerException):
        general = (
            f"Volatility experienced a layer-related issue: {exc.layer_name}"
        )
        detail = f"{exc}"
        caused_by = [f"A faulty layer implementation. {file_a_bug_msg}"]
    elif isinstance(exc, exceptions.MissingModuleException):
        general = (
            f"Volatility could not import a necessary module: {exc.module}"
        )
        detail = f"{exc}"
        caused_by = [
            "A required python module is not installed (install the module and re-run)"
        ]
    elif isinstance(exc, exceptions.RenderException):
        general = "Volatility experienced an issue when rendering the output:"
        detail = f"{exc}"
        caused_by = ["An invalid renderer option, such as no visible columns"]
    elif isinstance(exc, exceptions.VersionMismatchException):
        general = "A version mismatch was detected between two components:"
        detail = f"{exc}"
        caused_by = [
            exc.failure_reason or "An outdated API caller, such as a method.",
            file_a_bug_msg,
        ]
    else:
        general = "Volatility encountered an unexpected situation."
        detail = ""
        caused_by = [file_a_bug_msg]

    _LOGGER.error("%s", general)
    _LOGGER.error("%s", detail)
    for cause in caused_by:
        _LOGGER.error(" * %s", cause)


def setup_volatility3_framework():
    """Memory analysis module setup"""
    with _SETUP_LOCK:
        # skip subsequent calls to setup
        if _SETUP_FLAG.is_set():
            return
        _SETUP_FLAG.set()
        # check version
        require_interface_version(2, 0, 0)
        # configure plugin directories
        plugin_dirs = [
            Path(item).absolute()
            for item in getenv('PLASMA_VOL_PLUGIN_DIRS', '').split(';')
            if item and Path(item).absolute().is_dir()
        ]
        plugins.__path__ = [
            str(directory) for directory in plugin_dirs
        ] + constants.PLUGINS_PATH
        # configure symbol directories
        symbol_dirs = [
            Path(item).absolute()
            for item in getenv('PLASMA_VOL_SYMBOL_DIRS', '').split(';')
            if item and Path(item).absolute().is_dir()
        ]
        symbols.__path__ = [
            str(directory.absolute()) for directory in symbol_dirs
        ] + constants.SYMBOL_BASEPATHS
        # configure offline mode
        constants.OFFLINE = getenv('PLASMA_VOL_OFFLINE') is not None
        if not constants.OFFLINE:
            constants.REMOTE_ISF_URL = getenv(
                'PLASMA_VOL_REMOTE_ISF_URL', constants.REMOTE_ISF_URL
            )
        # configure cache
        constants.CACHE_PATH = getenv(
            'PLASMA_VOL_CACHE_PATH', constants.CACHE_PATH
        )
        if getenv('PLASMA_VOL_CACHE_CLEAR') is not None:
            clear_cache()
        # configure parallelism
        constants.PARALLELISM = constants.Parallelism.Off
        # import plugins
        failures = import_files(plugins, True)
        if failures:
            _LOGGER.warning(
                "volatility3 plugins import failures: %s", failures
            )


def run_volatility3_plugin(
    memdump: Path, plugin_name: str, plugin_config: dict | None = None
) -> Iterator[dict]:
    plugin_config = plugin_config or {}
    plugin_list = list_plugins()
    plugin = plugin_list[plugin_name]
    chosen_configurables_list = {}
    chosen_configurables_list[plugin] = plugin
    base_config_path = 'plugins'
    ctx = contexts.Context()
    automagics = automagic.available(ctx)
    plugin_config_path = interfaces.configuration.path_join(
        base_config_path, plugin.__name__
    )
    for key, val in plugin_config.items():
        ctx.config[f'{plugin_config_path}.{key}'] = val
    try:
        location = requirements.URIRequirement.location_from_file(str(memdump))
        ctx.config['automagic.LayerStacker.single_location'] = location
    except ValueError as exc:
        _LOGGER.exception("failed to load single location")
    automagics = automagic.choose_automagic(automagics, plugin)
    for amagic in automagics:
        chosen_configurables_list[amagic.__class__.__name__] = amagic
    if ctx.config.get('automagic.LayerStacker.stackers', None) is None:
        ctx.config['automagic.LayerStacker.stackers'] = (
            automagic.stacker.choose_os_stackers(plugin)
        )
    constructed = None
    try:
        constructed = construct_plugin(
            ctx,
            automagics,
            plugin,
            base_config_path,
            None,
            None,
        )
    except exceptions.UnsatisfiedException as exc:
        _log_unsatisfied_exception(exc)
    if not constructed:
        return
    try:
        grid = constructed.run()
    except exceptions.VolatilityException as exc:
        _log_exception(exc)
    function = partial(_visitor, columns=grid.columns)
    accumulator = grid.visit(
        node=None, function=function, initial_accumulator=[]
    )
    yield from accumulator
