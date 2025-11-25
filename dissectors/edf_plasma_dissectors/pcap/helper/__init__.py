"""PCAP helpers"""

from pathlib import Path

from edf_plasma_core.helper.importing import lazy_import
from edf_plasma_core.helper.selecting import select
from edf_plasma_core.helper.typing import PathIterator

lazy_scapy = lazy_import('scapy.all')
lazy_error = lazy_import('scapy.error')
SCAPY_AVAILABLE = lazy_scapy is not None


_PCAP_MAGIC_BYTES = {
    b'\xa1\xb2\x3c\x4d',  # pcap big-endian, nanosecond-resolution timestamp
    b'\xa1\xb2\xc3\xd4',  # pcap big-endian, microsecond-resolution timestamp
    b'\x4d\x3c\xb2\xa1',  # pcap little-endian, nanosecond-resolution timestamp
    b'\xd4\xc3\xb2\xa1',  # pcap little-endian, microsecond-resolution timestamp
    b'\x0a\x0d\x0d\x0a',  # pcapng
}


def is_pcap(filepath: Path):
    """Determine if filepath is a PCAP"""
    with filepath.open('rb') as fobj:
        return fobj.read(4) in _PCAP_MAGIC_BYTES


def select_pcap_impl(directory: Path) -> PathIterator:
    """Select pcap files in directory"""
    for filepath in select(directory, '*.pcap'):
        if not is_pcap(filepath):
            continue
        yield filepath


def disable_scapy_logging():
    """Remove handlers from scapy logger"""
    log_scapy = lazy_error.log_scapy
    for handler in log_scapy.handlers:
        log_scapy.removeHandler(handler)


def stream_pcap_packets(filepath: Path):
    """PCAP packet iterator"""
    yield from lazy_scapy.PcapReader(str(filepath))
