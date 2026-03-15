"""Darwin dissectors helper"""

from pathlib import Path
from plistlib import load


def load_plist(filepath: Path):
    """Load data from plist file"""
    with filepath.open('rb') as fobj:
        return load(fobj)
