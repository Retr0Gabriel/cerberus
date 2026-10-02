"""Proteção contra SSRF: o alvo não pode levar a ferramenta à rede interna."""

from __future__ import annotations

import httpx
import pytest

from collectors.analytics import AnalyticsCollector
from core.http_client import BlockedRequestError, HttpClient
from core.netguard import PublicHostGuard
from core.traffic import TrafficRecorder
from core.whois43 import Whois43Client, WhoisError


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    table: dict[str, list[str]] = {}

    async def resolve(host: str) -> list[str]:
        if host not in table:
            raise OSError("nome desconhecido")
        return table[host]

    monkeypatch.setattr("core.netguard._resolve", resolve)
    return table


@pytest.mark.parametrize(
    ("host", "blocked"),
    [
        ("169.254.169.254", True),  # metadados de nuvem
        ("127.0.0.1", True),
        ("10.0.0.5", True),
        ("192.168.0.1", True),
        ("[::1]", True),
        ("localhost", True),
        ("impressora.local", True),
        ("8.8.8.8", False),
        ("nao-resolve.example", False),  # sem DNS local: o proxy decide
    ],
)
async def test_guard_classifies_hosts(host: str, blocked: bool, fake_dns: dict) -> None:
    assert (await PublicHostGuard().reason_to_block(host) is not None) is blocked


async def test_guard_blocks_names_that_resolve_to_internal_ips(fake_dns: dict) -> None:
    fake_dns["evil.example"] = ["93.184.216.34", "10.0.0.5"]
    fake_dns["ok.example"] = ["93.184.216.34"]
    guard = PublicHostGuard()
    assert "10.0.0.5" in (await guard.reason_to_block("evil.example") or "")
    assert await guard.reason_to_block("ok.example") is None


async def test_redirect_to_cloud_metadata_is_blocked(fake_dns: dict) -> None:
    """Reproduz o ataque: a home do alvo redireciona para 169.254.169.254."""
    fake_dns["alvo.example"] = ["93.184.216.34"]
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host in ("alvo.example", "www.alvo.example"):
            return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/"})
        return httpx.Response(200, text='<a href="https://segredo-interno.corp/">x</a>')

    recorder = TrafficRecorder()
    async with HttpClient(
        retries=0,
        transport=httpx.MockTransport(handler),
        public_only=True,
        event_hooks=recorder.hooks,
    ) as http:
        result = await AnalyticsCollector(http).run("alvo.example")

    assert seen == ["https://alvo.example/", "https://www.alvo.example/"]  # nunca o 169.254
    assert not result.ok
    assert "destino bloqueado" in (result.error or "")
    assert any(e["response"]["status"] == 0 for e in recorder.entries)  # aparece no HAR


async def test_blocked_request_is_not_retried(fake_dns: dict) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200)

    async with HttpClient(
        retries=3, backoff=0, transport=httpx.MockTransport(handler), public_only=True
    ) as http:
        with pytest.raises(BlockedRequestError):
            await http.get("http://127.0.0.1/admin")
    assert calls == []


async def test_without_public_only_local_hosts_work() -> None:
    """O cliente do modelo de IA (Ollama em localhost) não usa a proteção."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    async with HttpClient(retries=0, transport=httpx.MockTransport(handler)) as http:
        assert await http.get_json("http://localhost:11434/v1/models") == {"ok": True}


async def test_whois_referral_to_internal_server_is_blocked(fake_dns: dict) -> None:
    client = Whois43Client(timeout=1.0, guard=PublicHostGuard())
    with pytest.raises(WhoisError, match="destino bloqueado"):
        await client.query("10.1.2.3", "acmelab.me")
