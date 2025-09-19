"""NTFS helper"""

_REASON_FLAGS = {
    0x00000001: 'DATA_OVERWRITE',
    0x00000002: 'DATA_EXTENDED',
    0x00000004: 'DATA_TRUNCATION',
    0x00000010: 'NAMED_DATA_OVERWRITE',
    0x00000020: 'NAMED_DATA_EXTEND',
    0x00000040: 'NAMED_DATA_TRUNCATION',
    0x00000100: 'FILE_CREATE',
    0x00000200: 'FILE_DELETE',
    0x00000400: 'EA_CHANGE',
    0x00000800: 'SECURITY_CHANGE',
    0x00001000: 'RENAME_OLD_NAME',
    0x00002000: 'RENAME_NEW_NAME',
    0x00004000: 'INDEXABLE_CHANGE',
    0x00008000: 'BASIC_INFO_CHANGE',
    0x00010000: 'HARD_LINK_CHANGE',
    0x00020000: 'COMPRESSION_CHANGE',
    0x00040000: 'ENCRYPTION_CHANGE',
    0x00080000: 'OBJECT_ID_CHANGE',
    0x00100000: 'REPARSE_POINT_CHANGE',
    0x00200000: 'STREAM_CHANGE',
    0x80000000: 'TRANSACTED_CHANGE',
}
_SOURCE_FLAGS = {
    0x00000001: 'DATA_MANAGEMENT',
    0x00000002: 'AUXILIARY_DATA',
    0x00000004: 'REPLICATION_MANAGEMENT',
    0x00000008: 'CLIENT_REPLICATION_MANAGEMENT',
}
_ATTR_FILE_NAME_FLAGS = {
    0x00000001: 'READONLY',
    0x00000002: 'HIDDEN',
    0x00000004: 'SYSTEM',
    0x00000020: 'ARCHIVE',
    0x00000040: 'DEVICE',
    0x00000080: 'NORMAL',
    0x00000100: 'TEMPORARY',
    0x00000200: 'SPARSE_FILE',
    0x00000400: 'REPARSE_POINT',
    0x00000800: 'COMPRESSED',
    0x00001000: 'OFFLINE',
    0x00002000: 'NOT_CONTENT_INDEXED',
    0x00004000: 'ENCRYPTED',
    0x10000000: 'DIRECTORY',
    0x20000000: 'INDEX_VIEW',
}


def _parse_generic_flags(flags: int, features: dict[int, str]) -> str:
    return '|'.join(
        [flag for value, flag in features.items() if flags & value == value]
    )


def parse_file_name_flags(flags: int) -> str:
    """Parse $MFT $FILE_NAME attribute flags"""
    return _parse_generic_flags(flags, _ATTR_FILE_NAME_FLAGS)


def parse_usnj_entry_source(flags: int) -> str:
    """Parse $UsnJrnl:$J entry source flags"""
    return _parse_generic_flags(flags, _SOURCE_FLAGS)


def parse_usnj_entry_reason(flags: int) -> str:
    """Parse $UsnJrnl:$J entry reason flags"""
    return _parse_generic_flags(flags, _REASON_FLAGS)
