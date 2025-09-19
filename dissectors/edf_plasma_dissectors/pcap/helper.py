"""PCAP parsing helper"""

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from edf_plasma_core.helper.datetime import (
    datetime,
    timedelta,
    timezone,
    to_iso_fmt,
)
from edf_plasma_core.helper.hashing import HashingAlgorithm, digest_from_bytes
from edf_plasma_core.helper.typing import PathIterator
from scapy.all import Packet, PcapReader
from scapy.error import log_scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.tls.all import TLSClientHello, TLSServerHello

# disable scapy logging handlers
for handler in log_scapy.handlers:
    log_scapy.removeHandler(handler)


UDP_HEADER_SIZE = 8
PCAP_MAGIC_BYTES = {
    b'\xa1\xb2\x3c\x4d',  # pcap big-endian, nanosecond-resolution timestamp
    b'\xa1\xb2\xc3\xd4',  # pcap big-endian, microsecond-resolution timestamp
    b'\x4d\x3c\xb2\xa1',  # pcap little-endian, nanosecond-resolution timestamp
    b'\xd4\xc3\xb2\xa1',  # pcap little-endian, microsecond-resolution timestamp
    b'\x0a\x0d\x0d\x0a',  # pcapng
}
TLS_EXT_SERVER_NAME = 0
TLS_EXT_SUPPORTED_GROUPS = 10
TLS_EXT_EC_POINT_FORMATS = 11


def is_pcap(filepath: Path):
    """Determine if filepath is a PCAP"""
    with filepath.open('rb') as fobj:
        return fobj.read(4) in PCAP_MAGIC_BYTES


def select_pcap_impl(directory: Path) -> PathIterator:
    """Select pcap files in directory"""
    for filepath in directory.rglob('*.pcap'):
        if not is_pcap(filepath):
            continue
        yield filepath


def stream_pcap_packets(filepath: Path):
    """PCAP packet iterator"""
    yield from PcapReader(str(filepath))


def pkt_time(pkt) -> datetime:
    """Extract time from packet"""
    dtv = datetime.fromtimestamp(int(pkt.time), tz=timezone.utc)
    microseconds = int(pkt.time * 1000000) % 1000000
    dtv += timedelta(microseconds=microseconds)
    return dtv


def udp_data_len(pkt):
    """Compute UDP data length in bytes"""
    return pkt[UDP].len - UDP_HEADER_SIZE


def tcp_data_len(pkt):
    """Compute TCP data length in bytes"""
    return len(pkt[TCP]) - (pkt[TCP].dataofs * 4)


def pkt_base_record(pkt):
    """Generic record for a packet"""
    net_header = None
    if IP in pkt:
        net_header = pkt[IP]
    if IPv6 in pkt:
        net_header = pkt[IPv6]
    if not net_header:
        return None
    tpt_header = None
    if TCP in pkt:
        tpt_header = pkt[TCP]
    if UDP in pkt:
        tpt_header = pkt[UDP]
    if not tpt_header:
        return None
    return {
        'pkt_time': to_iso_fmt(pkt_time(pkt)),
        'pkt_src_ip': net_header.src,
        'pkt_src_port': tpt_header.sport,
        'pkt_dst_ip': net_header.dst,
        'pkt_dst_port': tpt_header.dport,
    }


def decode_utf8_string(data: bytes):
    """Decode utf-8 bytes to string"""
    if isinstance(data, bytes):
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return data.hex()
    return data


def get_servernames(tls_client_hello: TLSClientHello):
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


def compute_ja3(tls_client_hello: TLSClientHello) -> tuple[str, str]:
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


def compute_ja3s(tls_server_hello: TLSServerHello):
    """https://github.com/salesforce/ja3/blob/master/README.md#ja3s"""
    version = str(tls_server_hello.version)
    cipher = str(tls_server_hello.cipher)
    extentions = '-'.join(map(lambda ext: str(ext.type), tls_server_hello.ext))
    ja3s_string = ','.join([version, cipher, extentions])
    ja3s_hash = digest_from_bytes(
        HashingAlgorithm.MD5, ja3s_string.encode('utf-8')
    )
    return ja3s_string, ja3s_hash


@dataclass
class UnidirectionalCounter:
    """A packet and data bytes counter"""

    pkt_cnt: int = 0
    data_bytes_cnt: int = 0

    def add(self, data_bytes_cnt: int, pkt_cnt: int = 1):
        """Add data bytes and packet count"""
        self.data_bytes_cnt += data_bytes_cnt
        self.pkt_cnt += pkt_cnt


@dataclass
class BidirectionalCounter:
    """A packet and bytes counter"""

    sent: UnidirectionalCounter = field(default_factory=UnidirectionalCounter)
    recv: UnidirectionalCounter = field(default_factory=UnidirectionalCounter)

    @property
    def pkt_total_cnt(self):
        """Total count of exchanged packets"""
        return self.sent.pkt_cnt + self.recv.pkt_cnt

    @property
    def data_bytes_total_cnt(self):
        """Total count of exchanged data bytes"""
        return self.sent.data_bytes_cnt + self.recv.data_bytes_cnt


@dataclass(frozen=True, eq=True)
class Peer:
    """A peer described by it address and port"""

    addr: str
    port: int


@dataclass(frozen=True, eq=True)
class PeerPair:
    """A pair of peers"""

    src_peer: Peer
    dst_peer: Peer

    @property
    def inverted(self) -> 'PeerPair':
        """Inverted pair, src becomes dst and dst becomes src"""
        return PeerPair(src_peer=self.dst_peer, dst_peer=self.src_peer)


@dataclass
class Conversation:
    """A conversation between two peers"""

    peer_pair: PeerPair
    beg_time: datetime | None = None
    end_time: datetime | None = None
    counter: BidirectionalCounter = field(default_factory=BidirectionalCounter)

    def as_record(self):
        """Record represenation for this instance"""
        return {
            'src_ip': self.peer_pair.src_peer.addr,
            'src_port': self.peer_pair.src_peer.port,
            'dst_ip': self.peer_pair.dst_peer.addr,
            'dst_port': self.peer_pair.dst_peer.port,
            'beg_time': to_iso_fmt(self.beg_time),
            'end_time': to_iso_fmt(self.end_time),
            'pkt_sent': self.counter.sent.pkt_cnt,
            'pkt_recv': self.counter.recv.pkt_cnt,
            'data_bytes_sent': self.counter.sent.data_bytes_cnt,
            'data_bytes_recv': self.counter.recv.data_bytes_cnt,
        }

    def append(self, peer_pair: PeerPair, pkt: Packet):
        """Append packet to conversation"""
        if not self.beg_time:
            self.beg_time = pkt_time(pkt)
        self.end_time = pkt_time(pkt)
        bytes_count = udp_data_len(pkt) if UDP in pkt else tcp_data_len(pkt)
        if peer_pair == self.peer_pair:
            self.counter.sent.add(bytes_count)
            return
        self.counter.recv.add(bytes_count)


ConversationIterator = Iterator[Conversation]


@dataclass
class TCPConversations:
    """TCP conversations aggregator"""

    mapping: dict[PeerPair, Conversation] = field(default_factory=dict)
    closed: list[Conversation] = field(default_factory=list)
    unbound: list[Packet] = field(default_factory=list)

    def append(self, peer_pair: PeerPair, pkt: Packet):
        """Add packet to associated conversation"""
        conv = self.mapping.get(peer_pair)
        if pkt[TCP].flags == 'S':
            if conv is not None:
                self.closed.append(conv)
            conv = Conversation(peer_pair=peer_pair)
            self.mapping[peer_pair] = conv
            self.mapping[peer_pair.inverted] = conv
        if conv is None:
            self.unbound.append(pkt)
            return
        conv.append(peer_pair, pkt)

    def conversations(self) -> ConversationIterator:
        """Conversations"""
        yield from self.closed
        seen = set()
        for conv in self.mapping.values():
            if conv.peer_pair in seen:
                continue
            seen.add(conv.peer_pair)
            yield conv


@dataclass
class UDPConversations:
    """UDP conversations aggregator"""

    mapping: dict[PeerPair, Conversation] = field(default_factory=dict)

    def append(self, peer_pair: PeerPair, pkt: Packet):
        """Add packet to associated conversation"""
        conv = self.mapping.get(peer_pair)
        if conv is None:
            conv = Conversation(peer_pair=peer_pair)
            self.mapping[peer_pair] = conv
            self.mapping[peer_pair.inverted] = conv
        conv.append(peer_pair, pkt)

    def conversations(self) -> ConversationIterator:
        """Conversations"""
        seen = set()
        for conv in self.mapping.values():
            if conv.peer_pair in seen:
                continue
            seen.add(conv.peer_pair)
            yield conv
