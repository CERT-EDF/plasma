"""TCP conversation helper"""

from dataclasses import dataclass, field

from .conv import Conversation, ConversationIterator, PeerPair


@dataclass
class UDPConversations:
    """UDP conversations aggregator"""

    mapping: dict[PeerPair, Conversation] = field(default_factory=dict)

    def append(self, peer_pair: PeerPair, pkt: 'scapy.all.Packet'):
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
