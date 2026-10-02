"""Cliente HTTP assíncrono centralizado (httpx) usado por todos os coletores."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from types import TracebackType
from typing import Any

import httpx

from core.netguard import BlockedDestinationError, PublicHostGuard
from core.version import VERSION

USER_AGENT = f"cerberus-osint/{VERSION} (+passive recon)"
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


class BlockedRequestError(httpx.RequestError):
    """Destino não público recusado pelo `PublicHostGuard` (não é repetido)."""


class HttpClient:
    """Wrapper de `httpx.AsyncClient` com timeout explícito e retry com backoff.

    `transport` permite injetar um transporte offline (modo --replay);
    `event_hooks` permite gravar o tráfego (`core.traffic.TrafficRecorder`);
    `public_only` recusa destinos internos em toda requisição e em cada salto de
    redirecionamento (proteção contra SSRF; ver `core.netguard`).
    """

    def __init__(
        self,
        timeout: float = 20.0,
        retries: int = 2,
        backoff: float = 1.0,
        transport: httpx.AsyncBaseTransport | None = None,
        event_hooks: Mapping[str, list[Any]] | None = None,
        public_only: bool = False,
    ) -> None:
        self.retries = retries
        self.backoff = backoff
        hooks = {k: list(v) for k, v in (event_hooks or {}).items()}
        # "error" é nosso (o httpx só conhece request/response): chamado em falha de rede
        self._error_hooks = list(hooks.pop("error", []))
        self.guard = PublicHostGuard() if public_only else None
        if self.guard is not None:
            hooks["request"] = [self._check_destination, *hooks.get("request", [])]
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
            transport=transport,
            event_hooks=hooks,
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, str | int] | None = None,
        headers: Mapping[str, str] | None = None,
        json: Any = None,
        retries: int | None = None,
        request_timeout: float | None = None,
    ) -> httpx.Response:
        """Requisição com retry em erros de rede e status 429/5xx.

        `retries` sobrescreve o padrão do cliente nesta chamada (fontes instáveis
        como o crt.sh pedem mais tentativas); `request_timeout` também (um modelo local
        pode levar minutos). Levanta `httpx.HTTPError` (ou subclasse) quando
        esgota as tentativas.
        """
        retries = self.retries if retries is None else retries
        extra: dict[str, Any] = (
            {} if request_timeout is None else {"timeout": httpx.Timeout(request_timeout)}
        )
        for attempt in range(retries + 1):
            last_attempt = attempt == retries
            try:
                resp = await self._client.request(
                    method, url, params=params, headers=headers, json=json, **extra
                )
            except BlockedRequestError as exc:
                for hook in self._error_hooks:
                    await hook(exc)
                raise
            except httpx.TransportError as exc:
                for hook in self._error_hooks:
                    await hook(exc)
                if last_attempt:
                    raise
            else:
                if resp.status_code not in RETRYABLE_STATUS or last_attempt:
                    resp.raise_for_status()
                    return resp
            await asyncio.sleep(self.backoff * (2**attempt))
        raise AssertionError("inalcançável")

    async def _check_destination(self, request: httpx.Request) -> None:
        assert self.guard is not None
        try:
            await self.guard.ensure_public(request.url.host)
        except BlockedDestinationError as exc:
            raise BlockedRequestError(str(exc), request=request) from exc

    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, str | int] | None = None,
        headers: Mapping[str, str] | None = None,
        retries: int | None = None,
    ) -> httpx.Response:
        return await self.request("GET", url, params=params, headers=headers, retries=retries)

    async def get_json(
        self,
        url: str,
        *,
        params: Mapping[str, str | int] | None = None,
        headers: Mapping[str, str] | None = None,
        retries: int | None = None,
    ) -> Any:
        resp = await self.get(url, params=params, headers=headers, retries=retries)
        return resp.json() if resp.content.strip() else None

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
