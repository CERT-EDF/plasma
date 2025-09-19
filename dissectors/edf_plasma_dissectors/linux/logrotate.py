"""Linux logrotate Dissector"""

from collections import defaultdict
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from shlex import split

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.streaming import lines_from_filepath
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator

_GLOB_PATTERN = 'logrotate.d/*'
_KEYWORD = {
    'compress',
    'compresscmd',
    'uncompresscmd',
    'compressext',
    'compressoptions',
    'copy',
    'copytruncate',
    'create',
    'daily',
    'dateext',
    'dateformat',
    'delaycompress',
    'extension',
    'ifempty',
    'include',
    'mail',
    'mailfirst',
    'maillast',
    'maxage',
    'minsize',
    'maxsize',
    'missingok',
    'monthly',
    'nocompress',
    'nocopy',
    'nocopytruncate',
    'nocreate',
    'nodelaycompress',
    'nodateext',
    'nomail',
    'nomissingok',
    'noolddir',
    'nosharedscripts',
    'noshred',
    'notifempty',
    'olddir',
    'postrotate',
    'prerotate',
    'firstaction',
    'lastaction',
    'endscript',
    'rotate',
    'size',
    'sharedscripts',
    'shred',
    'shredcycles',
    'start',
    'tabooext',
    'weekly',
    'yearly',
}
_BEG_SCRIPT = {
    'postrotate',
    'prerotate',
    'firstaction',
    'lastaction',
}
_END_SCRIPT = {
    'endscript',
}


@dataclass
class BlockContext:
    """Block context"""

    files: list[str] = field(default_factory=list)
    options: dict[str, str] = field(default_factory=dict)
    scripts: dict[str, list[str]] = field(
        default_factory=partial(defaultdict, list)
    )


@dataclass
class LCContext:
    """Logrotate configuration context"""

    files: list[str] = field(default_factory=list)
    blocks: list[BlockContext] = field(default_factory=list)
    options: dict[str, str] = field(default_factory=dict)
    scripts: dict[str, list[str]] = field(
        default_factory=partial(defaultdict, list)
    )
    in_block: bool = False
    in_script: str | None = None

    @property
    def active_ctx(self):
        """Active context"""
        return self.blocks[-1] if self.in_block else self

    def enter_block(self):
        """Enter block context"""
        bctx = BlockContext(files=list(self.files))
        self.files.clear()
        self.blocks.append(bctx)
        self.in_block = True

    def leave_block(self):
        """Leave block context"""
        self.in_block = False

    def enter_script(self, scriptname: str):
        """Enter script context"""
        self.in_script = scriptname

    def leave_script(self):
        """Leave script context"""
        self.in_script = None

    def add_line(self, line: str):
        """Add line to current context"""
        if self.in_script:
            self.active_ctx.scripts[self.in_script].append(line)
            return
        if self.in_block:
            raise ValueError(f"invalid logrotate format: {line}")
        self.files.append(line)

    def add_files(self, files: list[str]):
        """Add files to context"""
        for file in files:
            self.files.append(file)

    def add_option(self, line: str):
        """Add option to current context"""
        option = line.split(' ')
        self.active_ctx.options[option[0]] = ' '.join(option[1:])

    def generate_records(self) -> RecordIterator:
        """Generate records from context"""
        for block in self.blocks:
            for file in block.files:
                options = dict(self.options)
                options.update(block.options)
                for opt_name, opt_args in options.items():
                    yield {
                        'log_path': file,
                        'log_opt_name': opt_name,
                        'log_opt_args': opt_args,
                    }
                scripts = dict(self.scripts)
                scripts.update(block.scripts)
                for script_name, script_lines in scripts.items():
                    yield {
                        'log_path': file,
                        'log_opt_name': script_name,
                        'log_opt_args': '\n'.join(script_lines),
                    }


def _parse_option(lcctx: LCContext, line: str) -> bool:
    candidate = line.split(' ')[0]
    if candidate in _KEYWORD:
        if candidate in _BEG_SCRIPT:
            lcctx.enter_script(candidate)
            return True
        if candidate in _END_SCRIPT:
            lcctx.leave_script()
            return True
        lcctx.add_option(line)
        return True
    return False


def _parse_block_entry(lcctx: LCContext, line: str) -> bool:
    if line.endswith('{'):
        if len(line) > 1:
            lcctx.add_files(split(line)[:-1])
        lcctx.enter_block()
        return True
    return False


def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob(_GLOB_PATTERN):
        if not filepath.is_file():
            continue
        yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    lcctx = LCContext()
    for line in lines_from_filepath(ctx.filepath):
        line = line.strip()
        # skip comments and empty lines
        if not line or line.startswith('#'):
            continue
        # if line starts with option keyword
        if _parse_option(lcctx, line):
            continue
        # if line ends with start of block
        if _parse_block_entry(lcctx, line):
            continue
        # if line starts with end of block
        if line.endswith('}'):
            lcctx.leave_block()
            continue
        # from here, line must be a log filepath or a script line
        lcctx.add_line(line)
    yield from lcctx.generate_records()


DISSECTOR = Dissector(
    slug='linux_logrotate',
    tags={Tag.LINUX},
    columns=[
        Column('log_path', DataType.STR),
        Column('log_opt_name', DataType.STR),
        Column('log_opt_args', DataType.STR),
    ],
    description="logrotate configuration",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
