"""Transport UDP : sondes de découverte (unicast/broadcast/multicast)."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class ProbeKind(Enum):
    UNICAST = auto()
    BROADCAST = auto()
    MULTICAST = auto()


@dataclass(frozen=True)
class ProbeEndpoint:
    host: str
    port: int

    def tuple(self) -> tuple[str, int]:
        return (self.host, self.port)


@dataclass
class DatagramReply:
    source: tuple[str, int]
    payload: bytes


@dataclass
class _Receiver(asyncio.DatagramProtocol):
    replies: list[DatagramReply] = field(default_factory=list)

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.replies.append(DatagramReply(source=addr, payload=data))

    def error_received(self, exc: Exception) -> None:
        # erreur ICMP parasite (port non joignable) : ignorée pendant une découverte
        pass


def _make_socket(kind: ProbeKind, multicast_group: str | None = None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if kind is ProbeKind.BROADCAST:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    elif kind is ProbeKind.MULTICAST and multicast_group:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        group = socket.inet_aton(multicast_group)
        mreq = group + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        # autorise la répétition locale (caméra virtuelle inscrite sur le même groupe)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    return sock


async def udp_probe(
    request: bytes,
    endpoints: list[ProbeEndpoint],
    listen_window: float,
    *,
    kind: ProbeKind = ProbeKind.UNICAST,
    multicast_group: str | None = None,
) -> list[DatagramReply]:
    """Envoie `request` vers chaque endpoint et collecte les réponses pendant la
    fenêtre d'écoute `listen_window`.

    - UNICAST : chaque endpoint reçoit la requête, les réponses sont collectées pendant
      toute la fenêtre (mode simulateurs Phase 1).
    - BROADCAST/MULTICAST : la requête est envoyée vers l'adresse de diffusion, toutes
      les réponses reçues pendant la fenêtre sont collectées (mode réel).
    """
    loop = asyncio.get_running_loop()
    sock = _make_socket(kind, multicast_group)
    sock.bind(("0.0.0.0", 0))
    receiver = _Receiver()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: receiver, sock=sock
    )
    try:
        for ep in endpoints:
            transport.sendto(request, ep.tuple())
        await asyncio.sleep(listen_window)
        return list(receiver.replies)
    finally:
        transport.close()
