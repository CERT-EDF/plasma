"""ELF helpers"""

from pathlib import Path

from edf_plasma_core.dissector import DissectionContext
from edf_plasma_core.helper.importing import lazy_import
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.typing import PathIterator

lazy_lief = lazy_import('lief')
LIEF_AVAILABLE = lazy_lief is not None

_LOGGER = get_logger('dissectors.elf.helper')


def select_elf_impl(directory: Path) -> PathIterator:
    """Select ELF implementation"""
    for filepath in select(directory, '*'):
        if not lazy_lief.is_elf(str(filepath)):
            if filepath.suffix in {'.so'}:
                _LOGGER.warning(
                    "suffix suggests ELF but type check failed: %s"
                )
            continue
        yield filepath


def parse_elf(ctx: DissectionContext) -> 'lief.ELF.Binary':
    """Parse ELF file referenced by dissection context"""
    return lazy_lief.parse(ctx.filepath)


def elf_section_perm(section: 'lief.ELF.Section') -> str:
    """Build permission string from section"""
    p_r = section.has(lazy_lief.ELF.Section.FLAGS.ALLOC)
    p_w = section.has(lazy_lief.ELF.Section.FLAGS.WRITE)
    p_x = section.has(lazy_lief.ELF.Section.FLAGS.EXECINSTR)
    return ''.join(
        [
            'r' if p_r else '-',
            'w' if p_w else '-',
            'x' if p_x else '-',
        ]
    )


def elf_segment_perm(segment: 'lief.ELF.Segment') -> str:
    """Build permission string from section"""
    p_r = segment.has(lazy_lief.ELF.Segment.FLAGS.R)
    p_w = segment.has(lazy_lief.ELF.Segment.FLAGS.W)
    p_x = segment.has(lazy_lief.ELF.Segment.FLAGS.X)
    return ''.join(
        [
            'r' if p_r else '-',
            'w' if p_w else '-',
            'x' if p_x else '-',
        ]
    )


def elf_is_dt_needed(entry: 'lief.ELF.DynamicEntry') -> bool:
    """Determine if given entry is a DT_NEEDED entry"""
    return entry.tag == lazy_lief.ELF.DynamicEntry.TAG.NEEDED


def elf_fun_is_ctor_dtor(function) -> str | None:
    """Determine if fun is ctor, dtor or something else"""
    if lazy_lief.Function.FLAGS.CONSTRUCTOR in function.flags:
        return 'ctor'
    if lazy_lief.Function.FLAGS.DESTRUCTOR in function.flags:
        return 'dtor'
    return None
