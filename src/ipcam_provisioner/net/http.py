"""Client HTTP + résolution d'endpoint (mode réel / simulation).

En mode réel l'IP d'une caméra est joignable directement (port 80 par défaut) ; en
mode simulation (Phase 1) un resolver fourni par le réseau simulé fait correspondre
chaque IP logique à un endpoint localhost:port du simulateur.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx


@dataclass(frozen=True)
class ResolvedEndpoint:
    host: str
    port: int


class HttpEndpointResolver(Protocol):
    def resolve(self, ip: str) -> ResolvedEndpoint: ...


class NetworkResolver:
    """Résolution réseau réelle : l'IP de la caméra est atteinte telle quelle."""

    def __init__(self, port: int = 80) -> None:
        self._port = port

    def resolve(self, ip: str) -> ResolvedEndpoint:
        return ResolvedEndpoint(host=ip, port=self._port)


class HttpTalker:
    """Façade asyncio sur httpx, avec résolution d'endpoint injectable."""

    def __init__(self, resolver: HttpEndpointResolver, timeout: float = 5.0) -> None:
        self._resolver = resolver
        self._client = httpx.AsyncClient(timeout=timeout, follow_redirects=False)

    async def request(
        self,
        method: str,
        ip: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.Response:
        endpoint = self._resolver.resolve(ip)
        url = f"http://{endpoint.host}:{endpoint.port}{path}"
        return await self._client.request(
            method,
            url,
            params=params,
            content=content,
            headers=headers,
            auth=auth,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def resolver(self) -> HttpEndpointResolver:
        return self._resolver


def digest_auth(username: str, password: str) -> httpx.DigestAuth:
    return httpx.DigestAuth(username=username, password=password)


def basic_auth(username: str, password: str) -> httpx.BasicAuth:
    return httpx.BasicAuth(username=username, password=password)
