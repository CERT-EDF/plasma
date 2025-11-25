"""PE helpers"""

from pathlib import Path

from edf_plasma_core.dissector import DissectionContext
from edf_plasma_core.helper.importing import lazy_import
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.typing import PathIterator

lazy_lief = lazy_import('lief')
LIEF_AVAILABLE = lazy_lief is not None

_LOGGER = get_logger('dissectors.pe.helper')


def select_pe_impl(directory: Path) -> PathIterator:
    """Select PE implementation"""
    for filepath in select(directory, '*'):
        if not lazy_lief.is_pe(str(filepath)):
            if filepath.suffix.lower() in {'.exe', '.dll'}:
                _LOGGER.warning(
                    "suffix suggests PE but type check failed: %s", filepath
                )
            continue
        yield filepath


def parse_pe(ctx: DissectionContext) -> 'lief.PE.Binary':
    """Parse PE file referenced by dissection context"""
    return lazy_lief.parse(ctx.filepath)


def pe_pdb(pef: 'lief.PE.Binary') -> str:
    """Extract PDB path from PE binary if any"""
    for debug in pef.debug:
        if hasattr(debug, 'filename'):
            return getattr(debug, 'filename')
    return ''


def pe_imphash(pef: 'lief.PE.Binary') -> str:
    """Compute VirusTotal compatible imphash value for given PE binary"""
    return lazy_lief.PE.get_imphash(pef, lazy_lief.PE.IMPHASH_MODE.VT)


def pe_version(pef: 'lief.PE.Binary') -> str:
    """Build version string for given PE binary"""
    not_found = ''
    if not pef.has_resources:
        return not_found
    rsrc_mgr = pef.resources_manager
    if not rsrc_mgr.has_version:
        return not_found
    if not rsrc_mgr.version.has_fixed_file_info:
        return not_found
    ffi = rsrc_mgr.version.fixed_file_info
    return '.'.join(
        [
            str((ffi.file_version_MS >> 16) & 0xFFFF),
            str((ffi.file_version_MS) & 0xFFFF),
            str((ffi.file_version_LS >> 16) & 0xFFFF),
            str((ffi.file_version_LS) & 0xFFFF),
        ]
    )


def pe_sig_check(pef: 'lief.PE.Binary') -> bool:
    """Determine if PE signature is correct"""
    flag = pef.verify_signature()
    return str(flag).rsplit('.', 1)[-1]


def pe_section_perm(section: 'lief.PE.Section') -> str:
    """Convert some section characteristics to permission string"""
    r_p = section.has_characteristic(
        lazy_lief.PE.Section.CHARACTERISTICS.MEM_READ
    )
    w_p = section.has_characteristic(
        lazy_lief.PE.Section.CHARACTERISTICS.MEM_WRITE
    )
    x_p = section.has_characteristic(
        lazy_lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
    )
    return ''.join(
        ['r' if r_p else '-', 'w' if w_p else '-', 'x' if x_p else '-']
    )


def pe_section_is_code(section: 'lief.PE.Section') -> str:
    """Determine"""
    return section.has_characteristic(
        lazy_lief.PE.Section.CHARACTERISTICS.CNT_CODE
    )


def pe_certificate_key_type(certificate) -> str:
    """Get certificate key type as string"""
    mapping = {
        lazy_lief.PE.x509.KEY_TYPES.ECDSA: 'ECDSA',
        lazy_lief.PE.x509.KEY_TYPES.ECKEY: 'ECKEY',
        lazy_lief.PE.x509.KEY_TYPES.ECKEY_DH: 'ECKEY_DH',
        lazy_lief.PE.x509.KEY_TYPES.NONE: 'NONE',
        lazy_lief.PE.x509.KEY_TYPES.RSA: 'RSA',
        lazy_lief.PE.x509.KEY_TYPES.RSASSA_PSS: 'RSASSA_PSS',
        lazy_lief.PE.x509.KEY_TYPES.RSA_ALT: 'RSA_ALT',
    }
    return mapping.get(certificate.key_type, 'unknown')


def pe_fun_is_ctor_dtor(function) -> str | None:
    """Determine if fun is ctor, dtor or something else"""
    if lazy_lief.Function.FLAGS.CONSTRUCTOR in function.flags:
        return 'ctor'
    if lazy_lief.Function.FLAGS.DESTRUCTOR in function.flags:
        return 'dtor'
    return None
