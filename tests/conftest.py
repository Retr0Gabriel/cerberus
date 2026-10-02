"""Nenhum teste faz requisição real: todo tráfego httpx passa pelo respx (rotas
não mockadas falham) ou pelo ReplayTransport, e a chave do Claude é removida."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any, NoReturn

import httpx2
import pytest
import respx

from core.http_client import HttpClient

FIXTURES = Path(__file__).parent / "fixtures"
ACME_FIXTURE = FIXTURES / "acmecorp.json"
ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"


@pytest.fixture(autouse=True)
def respx_router() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


@pytest.fixture(autouse=True)
def block_httpx2_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """O SDK anthropic usa httpx2, que o respx não intercepta. Os testes devem criar
    o cliente com `create_anthropic_client(..., transport=...)`; qualquer tentativa de
    usar a rede real pelo httpx2 falha imediatamente."""

    def blocked(self: object, request: httpx2.Request) -> NoReturn:
        raise RuntimeError(f"rede real bloqueada nos testes: {request.url}")

    monkeypatch.setattr(httpx2.AsyncHTTPTransport, "handle_async_request", blocked)
    monkeypatch.setattr(httpx2.HTTPTransport, "handle_request", blocked)


@pytest.fixture(autouse=True)
def block_whois_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """O WHOIS da porta 43 usa sockets (não httpx): só servidores locais de teste."""
    real_open = asyncio.open_connection

    async def guarded(host: str, *args: Any, **kwargs: Any) -> Any:
        if host not in ("127.0.0.1", "localhost"):
            raise OSError(f"rede real bloqueada nos testes: {host}")
        return await real_open(host, *args, **kwargs)

    monkeypatch.setattr("core.whois43.asyncio.open_connection", guarded)


@pytest.fixture(autouse=True)
def block_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """A proteção contra SSRF resolve nomes; nos testes, nenhuma consulta DNS real
    (o resolvedor "falha" e o guarda deixa passar, como numa rede só com proxy)."""

    async def no_dns(host: str) -> list[str]:
        raise OSError(f"DNS real bloqueado nos testes: {host}")

    monkeypatch.setattr("core.netguard._resolve", no_dns)


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    names = ("MODEL", "LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")
    project_vars = [f"CERBERUS_{n}" for n in names]
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "CERTSPOTTER_API_KEY", *project_vars):
        monkeypatch.delenv(var, raising=False)
    # impede que um .env real do desenvolvedor seja carregado durante os testes
    monkeypatch.setattr("core.config.load_dotenv", lambda *a, **k: False)


@pytest.fixture
async def http() -> AsyncIterator[HttpClient]:
    async with HttpClient(timeout=5.0, retries=0, backoff=0.0) as client:
        yield client


def claude_tool_message(
    tool_input: dict[str, Any], name: str = "submit_analysis"
) -> dict[str, Any]:
    """Resposta da Messages API com um bloco tool_use (formato real da API)."""
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5-5",
        "stop_reason": "tool_use",
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 10},
        "content": [{"type": "tool_use", "id": "toolu_test", "name": name, "input": tool_input}],
    }
