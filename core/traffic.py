"""Gravação do tráfego HTTP em formato HAR (o mesmo dos navegadores e do Burp).

O `TrafficRecorder` usa os event hooks do httpx, então registra cada salto de
redirecionamento e respeita proxy/certificados do ambiente (HTTPS_PROXY,
SSL_CERT_FILE). Cabeçalhos com credenciais são mascarados antes de gravar.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from core.version import VERSION

SENSITIVE_HEADERS = frozenset(
    {"authorization", "x-api-key", "cookie", "set-cookie", "proxy-authorization"}
)
MAX_BODY_CHARS = 5_000_000
MASK = "***"


def _headers(headers: httpx.Headers) -> list[dict[str, str]]:
    return [
        {"name": k, "value": MASK if k.lower() in SENSITIVE_HEADERS else v}
        for k, v in headers.multi_items()
    ]


def _text(content: bytes) -> str:
    return content.decode("utf-8", errors="replace")[:MAX_BODY_CHARS]


class TrafficRecorder:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
        self._started: dict[int, tuple[datetime, float]] = {}

    @property
    def hooks(self) -> dict[str, list[Any]]:
        # "error" não é um hook do httpx: o HttpClient o chama em falhas de rede,
        # para que conexões recusadas e timeouts também apareçam no histórico
        return {
            "request": [self._on_request],
            "response": [self._on_response],
            "error": [self._on_error],
        }

    async def _on_request(self, request: httpx.Request) -> None:
        self._started[id(request)] = (datetime.now(UTC), time.monotonic())

    async def _on_response(self, response: httpx.Response) -> None:
        await response.aread()
        await self._record(response.request, response, None)

    async def _on_error(self, exc: httpx.TransportError) -> None:
        try:
            request = exc.request
        except RuntimeError:  # erro sem requisição associada
            return
        await self._record(request, None, exc)

    async def _record(
        self,
        request: httpx.Request,
        response: httpx.Response | None,
        error: Exception | None,
    ) -> None:
        started_at, t0 = self._started.pop(id(request), (datetime.now(UTC), time.monotonic()))
        elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
        req_body = await request.aread()  # saltos de redirect chegam em streaming
        if response is not None:
            resp_entry: dict[str, Any] = {
                "status": response.status_code,
                "statusText": response.reason_phrase,
                "httpVersion": response.http_version,
                "headers": _headers(response.headers),
                "cookies": [],
                "content": {
                    "size": len(response.content),
                    "mimeType": response.headers.get("content-type", ""),
                    "text": _text(response.content),
                },
                "redirectURL": response.headers.get("location", ""),
                "headersSize": -1,
                "bodySize": len(response.content),
            }
        else:  # HAR representa "sem resposta" com status 0
            message = f"{type(error).__name__}: {error}"
            resp_entry = {
                "status": 0,
                "statusText": message,
                "httpVersion": "",
                "headers": [],
                "cookies": [],
                "content": {"size": 0, "mimeType": "", "text": ""},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": -1,
                "_error": message,
            }
        entry: dict[str, Any] = {
            "startedDateTime": started_at.isoformat(),
            "time": elapsed_ms,
            "request": {
                "method": request.method,
                "url": str(request.url),
                "httpVersion": "HTTP/1.1",
                "headers": _headers(request.headers),
                "queryString": [
                    {"name": k, "value": v} for k, v in request.url.params.multi_items()
                ],
                "cookies": [],
                "headersSize": -1,
                "bodySize": len(req_body),
            },
            "response": resp_entry,
            "cache": {},
            "timings": {"send": 0, "wait": elapsed_ms, "receive": 0},
        }
        if req_body:
            entry["request"]["postData"] = {
                "mimeType": request.headers.get("content-type", ""),
                "text": _text(req_body),
            }
        self.entries.append(entry)

    def to_har(self) -> dict[str, Any]:
        entries = sorted(self.entries, key=lambda e: e["startedDateTime"])
        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "cerberus-osint", "version": VERSION},
                "entries": entries,
            }
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_har(), ensure_ascii=False, indent=1), encoding="utf-8"
        )


def load_har(path: str | Path) -> list[dict[str, Any]]:
    """Entradas de um arquivo HAR; ValueError com mensagem clara se ele for inválido."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return list(data["log"]["entries"])
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"arquivo HAR inválido ({path}): esperado log.entries ({exc})") from exc
