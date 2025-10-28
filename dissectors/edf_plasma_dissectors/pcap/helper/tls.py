"""TLS helpers"""

from edf_plasma_core.helper.hashing import HashingAlgorithm, digest_from_bytes
from edf_plasma_core.helper.importing import lazy_import

from .decode import decode_utf8_string

lazy_tls = lazy_import('scapy.layers.tls.all')

TLS_EXT_SERVER_NAME = 0
TLS_EXT_SUPPORTED_GROUPS = 10
TLS_EXT_EC_POINT_FORMATS = 11


def has_tls_cert(pkt: 'scapy.all.Packet') -> bool:
    """Determine if pkt has a TLSCertificate layer"""
    return lazy_tls.TLSCertificate in pkt


def tls_cert_layer(
    pkt: 'scapy.all.Packet',
) -> 'scapy.layers.tls.all.TLSCertificate':
    """retrieve pkt TLSCertificate layer"""
    return pkt[lazy_tls.TLSCertificate]


def has_tls_clt_hello(pkt: 'scapy.all.Packet') -> bool:
    """Determine if pkt has a TLSClientHello layer"""
    return lazy_tls.TLSClientHello in pkt


def tls_clt_hello_layer(
    pkt: 'scapy.all.Packet',
) -> 'scapy.layers.tls.all.TLSClientHello':
    """retrieve pkt TLSClientHello layer"""
    return pkt[lazy_tls.TLSClientHello]


def has_tls_srv_hello(pkt: 'scapy.all.Packet') -> bool:
    """Determine if pkt has a TLSServerHello layer"""
    return lazy_tls.TLSServerHello in pkt


def tls_srv_hello_layer(
    pkt: 'scapy.all.Packet',
) -> 'scapy.layers.tls.all.TLSServerHello':
    """retrieve pkt TLSServerHello layer"""
    return pkt[lazy_tls.TLSServerHello]


def get_servernames(tls_client_hello: 'scapy.layers.tls.all.TLSClientHello'):
    """Extract server names from TLS Hello Client message"""
    for ext in tls_client_hello.ext:
        if ext.type == TLS_EXT_SERVER_NAME:
            return ','.join(
                map(
                    lambda entry: decode_utf8_string(entry.servername),
                    ext.servernames,
                )
            )
    return None


def compute_ja3(
    tls_client_hello: 'scapy.layers.tls.all.TLSClientHello',
) -> tuple[str, str]:
    """https://github.com/salesforce/ja3/blob/master/README.md#how-it-works"""
    version = str(tls_client_hello.version)
    ciphers = '-'.join(map(str, tls_client_hello.ciphers))
    extentions = '-'.join(map(lambda ext: str(ext.type), tls_client_hello.ext))
    supported_groups = ''
    ec_point_formats = ''
    for ext in tls_client_hello.ext:
        if ext.type == TLS_EXT_SUPPORTED_GROUPS:
            supported_groups = '-'.join(map(str, ext.groups))
        if ext.type == TLS_EXT_EC_POINT_FORMATS:
            ec_point_formats = '-'.join(map(str, ext.ecpl))
    ja3_string = ','.join(
        [
            version,
            ciphers,
            extentions,
            supported_groups,
            ec_point_formats,
        ]
    )
    ja3_hash = digest_from_bytes(
        HashingAlgorithm.MD5, ja3_string.encode('utf-8')
    )
    return ja3_string, ja3_hash


def compute_ja3s(tls_server_hello: 'scapy.layers.tls.all.TLSServerHello'):
    """https://github.com/salesforce/ja3/blob/master/README.md#ja3s"""
    version = str(tls_server_hello.version)
    cipher = str(tls_server_hello.cipher)
    extentions = '-'.join(map(lambda ext: str(ext.type), tls_server_hello.ext))
    ja3s_string = ','.join([version, cipher, extentions])
    ja3s_hash = digest_from_bytes(
        HashingAlgorithm.MD5, ja3s_string.encode('utf-8')
    )
    return ja3s_string, ja3s_hash
