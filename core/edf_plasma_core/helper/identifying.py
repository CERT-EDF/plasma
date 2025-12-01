"""Identification helpers"""

from dataclasses import dataclass
from pathlib import Path

from magic import from_buffer, from_file
from magika import Magika


@dataclass
class IdentificationResult:
    """Identification result"""

    magic_mime: str
    magic_info: str
    magika_mime: str
    magika_info: str
    magika_label: str


def instanciate_magika() -> Magika:
    """Instanciate magika model once then give it as magika kwarg in
    identify_* functions
    """
    return Magika()


def identify_bytes(
    data: bytes, magika: Magika | None = None
) -> IdentificationResult:
    """Identify content type/format from bytes"""
    magika = magika or instanciate_magika()
    magika_result = magika.identify_bytes(data)
    return IdentificationResult(
        magic_mime=from_buffer(data, mime=True),
        magic_info=from_buffer(data, mime=False),
        magika_mime=magika_result.output.mime_type,
        magika_info=magika_result.output.description,
        magika_label=str(magika_result.output.label),
    )


def identify_filepath(
    filepath: Path, magika: Magika | None = None
) -> IdentificationResult:
    """Identify content type/format from filepath"""
    magika = magika or instanciate_magika()
    magika_result = magika.identify_path(filepath)
    return IdentificationResult(
        magic_mime=from_file(filepath, mime=True),
        magic_info=from_file(filepath, mime=False),
        magika_mime=magika_result.output.mime_type,
        magika_info=magika_result.output.description,
        magika_label=str(magika_result.output.label),
    )
