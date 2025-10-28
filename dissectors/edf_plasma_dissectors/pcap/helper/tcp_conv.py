"""TCP conversation helper"""

from dataclasses import dataclass, field

from .conv import Conversation, ConversationIterator, PeerPair
from .tcp import tcp_layer


@dataclass
class TCPConversations:
    """TCP conversations aggregator"""

    mapping: dict[PeerPair, Conversation] = field(default_factory=dict)
    closed: list[Conversation] = field(default_factory=list)
    unbound: list['scapy.all.Packet'] = field(default_factory=list)

    def append(self, peer_pair: PeerPair, pkt: 'scapy.all.Packet'):
        """Add packet to associated conversation"""
        conv = self.mapping.get(peer_pair)
        if tcp_layer(pkt).flags == 'S':
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
