"""Mini-serveur HTTP asyncio utilisé par les caméras simulées (Phase 1).

Implémente la portion minimale de HTTP/1.1 nécessaire aux simulateurs : requêtes
GET/POST avec headers et corps, réponse avec en-têtes. Suffisant pour imiter les
API ISAPI (Hikvision), CGI (Dahua) et ONVIF/WS-Security.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit


@dataclass
class HttpRequest:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: bytes

    def header(self, name: str) -> str | None:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None


@dataclass
class HttpResponse:
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @classmethod
    def text(cls, status: int, text: str, **headers: str) -> HttpResponse:
        body = text.encode("utf-8")
        hdrs = {"Content-Type": "text/xml; charset=utf-8", **headers}
        return cls(status=status, headers=hdrs, body=body)

    @classmethod
    def unauthorized_digest(cls, realm: str = "IP Camera") -> HttpResponse:
        from ..auth import build_www_authenticate_digest

        return cls(
            status=401,
            headers={"WWW-Authenticate": build_www_authenticate_digest(realm)},
            body=b"Unauthorized",
        )

    @classmethod
    def unauthorized_basic(cls, realm: str = "Camera") -> HttpResponse:
        return cls(
            status=401,
            headers={"WWW-Authenticate": f'Basic realm="{realm}"'},
            body=b"Unauthorized",
        )


Handler = Callable[[HttpRequest], Awaitable[HttpResponse]]

_REASONS = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
}


class FakeHttpserver:
    def __init__(self, handler: Handler) -> None:
        self._handler = handler
        self._server: asyncio.Server | None = None
        self.host = "127.0.0.1"
        self.port = 0

    async def start(self) -> int:
        self._server = await asyncio.start_server(
            self._on_client, host=self.host, port=0
        )
        self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _on_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            request = await self._read_request(reader)
            response = await self._handler(request)
        except (asyncio.IncompleteReadError, ValueError):
            response = HttpResponse(
                status=400, headers={"Connection": "close"}, body=b"Bad Request"
            )
        except Exception:  # noqa: BLE001 - isole l'erreur du serveur simulé
            response = HttpResponse(
                status=500, headers={"Connection": "close"}, body=b"Server Error"
            )
        try:
            await self._write_response(writer, response)
        finally:
            writer.close()

    @staticmethod
    async def _read_request(reader: asyncio.StreamReader) -> HttpRequest:
        request_line = (await reader.readuntil(b"\r\n")).decode("latin-1").strip()
        parts = request_line.split(" ")
        if len(parts) != 3:
            raise ValueError("Requête HTTP malformée")
        method, target, _version = parts
        split = urlsplit(target)
        headers: dict[str, str] = {}
        while True:
            line = (await reader.readuntil(b"\r\n")).decode("latin-1")
            if line in ("\r\n", "\n", ""):
                break
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        content_length = int(headers.get("content-length", "0"))
        body = await reader.readexactly(content_length) if content_length else b""
        query = {k: v for k, v in parse_qs(split.query).items()}
        return HttpRequest(
            method=method.upper(),
            path=split.path,
            headers=headers,
            query=query,
            body=body,
        )

    @staticmethod
    async def _write_response(
        writer: asyncio.StreamWriter, response: HttpResponse
    ) -> None:
        status = _REASONS.get(response.status, "Unknown")
        headers = {
            "Content-Length": str(len(response.body)),
            "Connection": "close",
            **response.headers,
        }
        lines = [f"HTTP/1.1 {response.status} {status}"]
        lines.extend(f"{name}: {value}" for name, value in headers.items())
        payload = "\r\n".join(lines) + "\r\n\r\n"
        writer.write(payload.encode("latin-1") + response.body)
        await writer.drain()
