"""WHOIS da porta 43 contra um servidor TCP local (o protocolo real, sem rede externa)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
import respx

from collectors.whois import WhoisCollector
from core.http_client import HttpClient
from core.whois43 import Whois43Client, WhoisError, lookup, parse_whois

IANA_ME = """\
% IANA WHOIS server
domain:       ME
organisation: Government of Montenegro
whois:        whois.nic.me
status:       ACTIVE
"""

REGISTRY_ZT = """\
Domain Name: ACMELAB.ME
Registrar WHOIS Server: whois.registrar.example
Updated Date: 2024-01-01T00:00:00Z
Creation Date: 2011-06-29T00:00:00Z
Registry Expiry Date: 2027-06-29T00:00:00Z
Registrar: Exemplo Registrar Ltd
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: Acme Labs
Registrant Email: Please query the RDDS service of the Registrar of Record
Tech Email: tech@acmedns.net
Name Server: NS1.ACMEDNS.NET
Name Server: NS2.ACMEDNS.NET
>>> Last update of WHOIS database: 2026-10-01T00:00:00Z <<<
"""

REGISTRAR_ZT = """\
Domain Name: acmelab.me
Registrar: Exemplo Registrar Ltd
Registrant Organization: Acme Labs
Admin Email: admin@acmelabs.org
Name Server: ns1.acmedns.net
"""


class Routed(Whois43Client):
    """Envia tudo ao servidor local, prefixando o servidor pedido na consulta."""

    def __init__(self, port: int) -> None:
        super().__init__(timeout=2.0, port=port)
        self.asked: list[tuple[str, str]] = []

    async def query(self, server: str, text: str) -> str:
        self.asked.append((server, text))
        return await super().query("127.0.0.1", f"{server} {text}")


@pytest.fixture
async def whois_server() -> AsyncIterator[tuple[dict[str, str], int]]:
    answers: dict[str, str] = {}

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        line = (await reader.readline()).decode().strip()
        writer.write(answers.get(line, "").encode())
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield answers, port


def test_parse_whois_keeps_org_registrar_dates_and_email_domains_only() -> None:
    meta, related = parse_whois(REGISTRY_ZT)
    assert meta["registrar"] == "Exemplo Registrar Ltd"
    assert meta["organizations"] == ["Acme Labs"]
    assert meta["nameservers"] == ["ns1.acmedns.net", "ns2.acmedns.net"]
    assert meta["contact_email_domains"] == ["acmedns.net"]
    assert meta["events"] == {
        "last changed": "2024-01-01T00:00:00Z",
        "registration": "2011-06-29T00:00:00Z",
        "expiration": "2027-06-29T00:00:00Z",
    }
    assert "REDACTED" not in str(meta)  # nada de campos ocultados
    assert ("ns1.acmedns.net", "nameserver no WHOIS") in related


async def test_lookup_follows_iana_and_registrar_referrals(
    whois_server: tuple[dict[str, str], int],
) -> None:
    answers, port = whois_server
    answers["whois.iana.org me"] = IANA_ME
    answers["whois.nic.me acmelab.me"] = REGISTRY_ZT
    answers["whois.registrar.example acmelab.me"] = REGISTRAR_ZT
    client = Routed(port)

    server, text = await lookup(client, "acmelab.me")
    assert client.asked == [
        ("whois.iana.org", "me"),
        ("whois.nic.me", "acmelab.me"),
        ("whois.registrar.example", "acmelab.me"),
    ]
    assert server == "whois.registrar.example"
    assert "admin@acmelabs.org" in text


async def test_lookup_keeps_registry_answer_when_registrar_is_empty(
    whois_server: tuple[dict[str, str], int],
) -> None:
    answers, port = whois_server
    answers["whois.iana.org me"] = IANA_ME
    answers["whois.nic.me acmelab.me"] = REGISTRY_ZT  # registrar sem resposta
    server, text = await lookup(Routed(port), "acmelab.me")
    assert server == "whois.nic.me"
    assert "NS1.ACMEDNS.NET" in text


async def test_client_reports_unreachable_port() -> None:
    client = Whois43Client(
        timeout=10.0, port=1
    )  # nada escuta na porta 1 (no Windows, a recusa leva ~2s)
    with pytest.raises(WhoisError, match="inacessível"):
        await client.query("127.0.0.1", "acmelab.me")


async def test_collector_falls_back_to_port43_when_tld_has_no_rdap(
    respx_router: respx.MockRouter,
    http: HttpClient,
    whois_server: tuple[dict[str, str], int],
) -> None:
    answers, port = whois_server
    answers["whois.iana.org me"] = IANA_ME
    answers["whois.nic.me acmelab.me"] = REGISTRY_ZT
    respx_router.get("https://rdap.org/domain/acmelab.me").respond(404)
    respx_router.get("https://data.iana.org/rdap/dns.json").respond(
        json={"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}
    )

    result = await WhoisCollector(http, Routed(port)).run("acmelab.me")
    assert result.ok, result.error
    assert result.metadata["protocol"] == "whois (porta 43)"
    assert result.metadata["whois_server"] == "whois.nic.me"
    assert result.metadata["organizations"] == ["Acme Labs"]
    assert {f.domain for f in result.findings} == {
        "ns1.acmedns.net",
        "ns2.acmedns.net",
        "acmedns.net",
    }


async def test_collector_explains_when_port43_is_blocked(
    respx_router: respx.MockRouter, http: HttpClient
) -> None:
    respx_router.get("https://rdap.org/domain/acmelab.me").respond(404)
    respx_router.get("https://data.iana.org/rdap/dns.json").respond(json={"services": []})
    blocked = Whois43Client(timeout=10.0, port=1)
    result = await WhoisCollector(http, blocked).run("acmelab.me")
    assert not result.ok
    assert "não publica dados RDAP e o WHOIS na porta 43 falhou" in (result.error or "")
