"""Matching helper"""

from re import compile as regexp

from yarl import URL

from .typing import StringIterator, URLIterator

URL_PATTERN = regexp(r'(?P<url>https?://[^\s]+)')


def iter_url(candidate: str) -> URLIterator:
    """Iterate over URL matched in candidate"""
    for match in URL_PATTERN.finditer(candidate):
        yield URL(match.group('url'))


def iter_url_fqdn(candidate: str) -> StringIterator:
    """Iterate over URL FQDN matched in candidate"""
    for url in iter_url(candidate):
        yield url.host
        # additional processing for safelinks
        if url.host.endswith('.safelinks.protection.outlook.com'):
            yield URL(url.query['url']).host
