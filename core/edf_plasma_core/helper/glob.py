"""Glob helpers"""

from .matching import regexp

AZ_PATTERN = regexp(r'[a-z]')


def _ci_glob_repl(match):
    char = match.group(0)
    return f'[{char.upper()}{char}]'


def ci_glob_pattern(pattern: str):
    """Convert a glob pattern to its case insensitive equivalent"""
    return AZ_PATTERN.sub(_ci_glob_repl, pattern.lower())
