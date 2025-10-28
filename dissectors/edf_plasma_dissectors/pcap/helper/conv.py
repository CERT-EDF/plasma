"""Conversation helpers"""

from collections.abc import Iterator
from dataclasses import dataclass, field

from edf_plasma_core.helper.datetime import datetime, to_iso_fmt

from .packet import pkt_time
from .tcp import tcp_data_len
from .udp import has_udp, udp_data_len


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

    def append(self, peer_pair: PeerPair, pkt: 'scapy.all.Packet'):
        """Append packet to conversation"""
        if not self.beg_time:
            self.beg_time = pkt_time(pkt)
        self.end_time = pkt_time(pkt)
        bytes_count = udp_data_len(pkt) if has_udp(pkt) else tcp_data_len(pkt)
        if peer_pair == self.peer_pair:
            self.counter.sent.add(bytes_count)
            return
        self.counter.recv.add(bytes_count)


ConversationIterator = Iterator[Conversation]
