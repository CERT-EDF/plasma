"""ELF helpers"""

from pathlib import Path

from edf_plasma_core.dissector import DissectionContext
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.typing import PathIterator
from lief import ELF, Function, is_elf, parse

_LOGGER = get_logger('dissectors.elf.helper')


def select_elf_impl(directory: Path) -> PathIterator:
    """Select ELF implementation"""
    for filepath in directory.rglob('*'):
        if not filepath.is_file():
            continue
        if not is_elf(str(filepath)):
            if filepath.suffix in {'.so'}:
                _LOGGER.warning(
                    "suffix suggests ELF but type check failed: %s"
                )
            continue
        yield filepath


def parse_elf(ctx: DissectionContext) -> ELF.Binary:
    """Parse ELF file referenced by dissection context"""
    return parse(ctx.filepath)


def elf_section_perm(section: ELF.Section) -> str:
    """Build permission string from section"""
    p_r = section.has(ELF.Section.FLAGS.ALLOC)
    p_w = section.has(ELF.Section.FLAGS.WRITE)
    p_x = section.has(ELF.Section.FLAGS.EXECINSTR)
    return ''.join(
        [
            'r' if p_r else '-',
            'w' if p_w else '-',
            'x' if p_x else '-',
        ]
    )


def elf_segment_perm(segment: ELF.Segment) -> str:
    """Build permission string from section"""
    p_r = segment.has(ELF.Segment.FLAGS.R)
    p_w = segment.has(ELF.Segment.FLAGS.W)
    p_x = segment.has(ELF.Segment.FLAGS.X)
    return ''.join(
        [
            'r' if p_r else '-',
            'w' if p_w else '-',
            'x' if p_x else '-',
        ]
    )


def elf_is_dt_needed(entry: ELF.DynamicEntry) -> bool:
    """Determine if given entry is a DT_NEEDED entry"""
    return entry.tag == ELF.DynamicEntry.TAG.NEEDED


def elf_fun_is_ctor_dtor(function) -> str | None:
    """Determine if fun is ctor, dtor or something else"""
    if Function.FLAGS.CONSTRUCTOR in function.flags:
        return 'ctor'
    if Function.FLAGS.DESTRUCTOR in function.flags:
        return 'dtor'
    return None
