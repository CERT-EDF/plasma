"""Hashing helpers"""

from enum import Enum
from hashlib import md5, sha1, sha256
from pathlib import Path

from .streaming import chunks_from_filepath


class HashingAlgorithm(Enum):
    """Hashing algorithm"""

    MD5 = 'md5'
    SHA1 = 'sha1'
    SHA256 = 'sha256'


_HASH_ALGORITHM_MAP = {
    HashingAlgorithm.MD5: md5,
    HashingAlgorithm.SHA1: sha1,
    HashingAlgorithm.SHA256: sha256,
}


def digest_from_bytes(hash_algo: HashingAlgorithm, data: bytes) -> str:
    """Digest from bytes using given hashing algorithm"""
    mda = _HASH_ALGORITHM_MAP[hash_algo]()
    mda.update(data)
    return mda.hexdigest()


def digest_from_filepath(hash_algo: HashingAlgorithm, filepath: Path) -> str:
    """Digest from file path using given hashing algorithm"""
    mda = _HASH_ALGORITHM_MAP[hash_algo]()
    for chunk in chunks_from_filepath(filepath):
        mda.update(chunk)
    return mda.hexdigest()
