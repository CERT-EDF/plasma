"""Metadata helper"""

from collections.abc import Iterator
from gzip import open as gzip_open
from json import JSONDecodeError, dump, dumps, load, loads
from pathlib import Path

from .logging import get_logger

_LOGGER = get_logger('core.helper.json')

JSONSerializableType = (
    str
    | int
    | bool
    | float
    | list['JSONSerializableType']
    | dict[str, 'JSONSerializableType']
    | None
)
JSONSerializableIterator = Iterator[JSONSerializableType]


def _read_jsonl_fobj(fobj) -> JSONSerializableIterator:
    for index, line in enumerate(fobj):
        line = line.rstrip()
        if not line:
            continue
        try:
            yield loads(line)
        except JSONDecodeError as exc:
            _LOGGER.warning("malformed JSON at line %d", index + 1)
            _LOGGER.warning("details: %s", exc)


def _write_jsonl_fobj(fobj, records: JSONSerializableIterator):
    for record in records:
        fobj.write(dumps(record, separators=(',', ':')))
        fobj.write('\n')


def read_json(filepath: Path) -> JSONSerializableType | None:
    """Load object from JSON content stored in filepath"""
    with filepath.open() as fobj:
        try:
            return load(fobj)
        except JSONDecodeError as exc:
            _LOGGER.warning("malformed JSON in %s", filepath)
            _LOGGER.warning("details: %s", exc)
            return None


def read_jsonl(filepath: Path) -> JSONSerializableIterator:
    """Load objects from newline delimited JSON content stored in filepath"""
    with filepath.open(encoding='utf-8') as fobj:
        yield from _read_jsonl_fobj(fobj)


def read_jsonl_gz(filepath: Path) -> JSONSerializableIterator:
    """Iterate over gzipped CSV records"""
    with gzip_open(filepath, 'rt', encoding='utf-8', newline='') as fobj:
        yield from _read_jsonl_fobj(fobj)


def write_jsonl_gz(filepath: Path, records: JSONSerializableIterator):
    """Write records to gzipped CSV"""
    with gzip_open(filepath, 'wt', encoding='utf-8', newline='') as fobj:
        _write_jsonl_fobj(fobj, records)


class JSONSerializable:
    """JSON serializable API"""

    @classmethod
    def from_dict(cls, dct: JSONSerializableType):
        """Build instance from dict"""
        raise NotImplementedError("subclass failed to implement .from_dict()")

    @classmethod
    def from_filepath(cls, filepath: Path):
        """Build instance from JSON data stored in filepath"""
        if not filepath.is_file():
            return cls.from_dict({})
        dct = read_json(filepath)
        if dct is None:
            return cls.from_dict({})
        return cls.from_dict(dct)

    def to_dict(self) -> JSONSerializableType:
        """Convert instance to dict"""
        raise NotImplementedError("subclass failed to implement .to_dict()")

    def to_string(self) -> str:
        """Convert instance to JSON string"""
        return dumps(self.to_dict())

    def to_filepath(self, filepath: Path):
        """Store instance as JSON data in filepath"""
        with filepath.open('w') as fobj:
            dump(self.to_dict(), fobj)
