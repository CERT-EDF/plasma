"""Cryptography helpers"""

from collections import Counter
from math import log
from pathlib import Path

from .streaming import chunks_from_filepath


def entropy_from_filepath(filepath: Path) -> float:
    """Entropy from filepath content"""
    ent = 0
    seen = Counter()
    length = 0
    for chunk in chunks_from_filepath(filepath):
        length += len(chunk)
        seen.update(chunk)
    if not length:
        return ent
    for byte in range(256):
        p_byte = float(seen.get(byte, 0)) / length
        if p_byte > 0:
            ent -= p_byte * log(p_byte, 2)
    return ent


def entropy_from_bytes(data: bytes) -> float:
    """Entropy from bytes"""
    ent = 0
    seen = Counter()
    length = len(data)
    if not length:
        return ent
    seen.update(data)
    for byte in range(0, 256):
        p_byte = float(seen.get(byte, 0)) / length
        if p_byte > 0:
            ent -= p_byte * log(p_byte, 2)
    return ent
