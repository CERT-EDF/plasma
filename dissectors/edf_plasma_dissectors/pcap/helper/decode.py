"""Decode helper"""


def decode_utf8_string(data: bytes):
    """Decode utf-8 bytes to string"""
    if isinstance(data, bytes):
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return data.hex()
    return data
