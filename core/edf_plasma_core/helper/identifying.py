"""Identification helpers"""

from dataclasses import dataclass
from pathlib import Path

from magic import from_buffer, from_file
from magika import Magika
from magika.types import MagikaResult


@dataclass
class IdentificationResult:
    """Identification result"""

    mime: bool
    magic_output: str
    magika_output: str


def _parse_magika_result(
    magika_result: MagikaResult, mime: bool = True
) -> str:
    magika_output = magika_result.output
    return magika_output.mime_type if mime else magika_output.magic


def instanciate_magika() -> Magika:
    """Instanciate magika model once then give it as magika kwarg in
    identify_* functions
    """
    return Magika()


def identify_bytes(
    data: bytes, mime: bool = True, magika: Magika | None = None
) -> IdentificationResult:
    """Identify content type/format from bytes"""
    magika = magika or instanciate_magika()
    magika_result = magika.identify_bytes(data)
    return IdentificationResult(
        mime=mime,
        magic_output=from_buffer(data, mime=mime),
        magika_output=_parse_magika_result(magika_result),
    )


def identify_filepath(
    filepath: Path, mime: bool = True, magika: Magika | None = None
) -> IdentificationResult:
    """Identify content type/format from filepath"""
    magika = magika or instanciate_magika()
    magika_result = magika.identify_path(filepath)
    return IdentificationResult(
        mime=mime,
        magic_output=from_file(filepath, mime=mime),
        magika_output=_parse_magika_result(magika_result),
    )
