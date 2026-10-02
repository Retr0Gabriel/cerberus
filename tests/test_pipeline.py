from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from collectors import build_collectors
from core.http_client import HttpClient
from core.llm import ClaudeAnalyzer, create_anthropic_client
from core.pipeline import analyze, collect_all
from core.replay import ReplayTransport
from tests.conftest import ACME_FIXTURE

ORG = "Acme Corp S.A."


@pytest.fixture
def replay() -> ReplayTransport:
    return ReplayTransport.from_file(ACME_FIXTURE)


@pytest.fixture
async def offline_http(replay: ReplayTransport) -> AsyncIterator[HttpClient]:
    async with HttpClient(retries=0, transport=replay) as client:
        yield client


@pytest.fixture
async def offline_analyzer(replay: ReplayTransport) -> AsyncIterator[ClaudeAnalyzer]:
    async with create_anthropic_client("replay", transport=replay, max_retries=0) as client:
        yield ClaudeAnalyzer(client, model="claude-opus-5-5")


async def test_heuristic_pipeline_offline(offline_http: HttpClient):
    report = await analyze("https://www.AcmeCorp.com.br/", build_collectors(offline_http, org=ORG))
    assert report.target == "acmecorp.com.br"
    assert report.analyzer == "heuristica"
    assert report.collector_errors == {}

    subs = {m.domain for m in report.by_category("subdominio")}
    assert subs == {
        "www.acmecorp.com.br",
        "api.acmecorp.com.br",
        "vpn.acmecorp.com.br",
        "loja.acmecorp.com.br",
        "blog.acmecorp.com.br",
        "dev.acmecorp.com.br",
    }
    related = {m.domain for m in report.by_category("relacionado")}
    assert {
        "acmepay.com.br",
        "acme-labs.io",
        "acmestore.com",
        "acmecorp.com",
        "acmecorp.net",
    } <= related
    third = {m.domain for m in report.by_category("terceiros")}
    assert {"aspmx.l.google.com", "b.sec.dns.br", "ag.dmarcian.com", "www.instagram.com"} <= third

    acmepay = next(m for m in report.matches if m.domain == "www.acmepay.com.br")
    assert acmepay.sources == ["analytics_link", "crtsh_org"]  # duas fontes independentes

    # redução de ruído: variação de TLD com o DNS próprio do alvo é sinal forte;
    # estacionada em terceiros continua fraca; link solto na home é o mais fraco
    by_domain = {m.domain: m for m in report.matches}
    assert by_domain["acmecorp.com"].sources == ["tld_variants_ns"]
    assert by_domain["acmecorp.com"].confidence == 0.6
    # estacionado na ParkingCrew: quase certamente de outro dono
    assert by_domain["acmecorp.net"].sources == ["tld_variants_parked"]
    assert by_domain["acmecorp.net"].confidence == 0.05
    assert by_domain["www.instagram.com"].confidence == 0.15


async def test_claude_pipeline_offline_filters_false_positives(
    offline_http: HttpClient, offline_analyzer: ClaudeAnalyzer
):
    report = await analyze(
        "acmecorp.com.br", build_collectors(offline_http, org=ORG), offline_analyzer
    )
    assert report.analyzer == "claude"
    assert report.summary.startswith("A Acme Corp")
    assert {fp.domain for fp in report.false_positives} == {"acmecorp.net", "www.instagram.com"}

    by_domain = {m.domain: m for m in report.matches}
    assert "acmecorp.net" not in by_domain
    assert "dominio-inventado.com" not in by_domain
    assert by_domain["acmepay.com.br"].confidence == 0.9
    assert by_domain["dmarc-acme.com"].reasoning == "não avaliado pelo modelo"


async def test_failing_collector_does_not_break_pipeline(replay: ReplayTransport):
    rules = [r for r in replay.rules if "crt.sh" not in r["url"]]
    async with HttpClient(retries=0, transport=ReplayTransport(rules)) as http:
        report = await analyze("acmecorp.com.br", build_collectors(http, org=ORG))
    assert set(report.collector_errors) == {"crtsh"}
    assert any(m.domain == "loja.acmecorp.com.br" for m in report.matches)


async def test_claude_failure_falls_back_to_heuristic(
    replay: ReplayTransport, offline_http: HttpClient
):
    # transporte sem a regra da Anthropic: a API "responde" 404
    rules = [r for r in replay.rules if "anthropic" not in r["url"]]
    client = create_anthropic_client("replay", transport=ReplayTransport(rules), max_retries=0)
    async with client:
        report = await analyze(
            "acmecorp.com.br",
            build_collectors(offline_http, org=ORG),
            ClaudeAnalyzer(client, model="claude-opus-5-5"),
        )
    assert report.analyzer == "heuristica"
    assert report.warnings and "falha na API" in report.warnings[0]
    assert report.matches


async def test_invalid_target(offline_http: HttpClient):
    with pytest.raises(ValueError, match="domínio inválido"):
        await analyze("não é domínio", build_collectors(offline_http))


async def test_heuristic_scores_and_categories(offline_http: HttpClient) -> None:
    collectors = build_collectors(offline_http)
    raw = await collect_all(collectors, "acmecorp.com.br")
    report = await analyze("acmecorp.com.br", collectors)

    by_domain = {m.domain: m for m in report.matches}
    # nameserver próprio visto no DNS e no WHOIS: pista forte
    assert by_domain["ns1.acmedns.com.br"].sources == ["dns", "whois"]
    assert by_domain["ns1.acmedns.com.br"].confidence == 0.8
    # outra marca no mesmo certificado
    assert by_domain["acmestore.com"].category == "relacionado"
    # mesmo nome em outro TLD, mas estacionado: quase nada; link solto na home, pouco
    assert by_domain["acmecorp.net"].sources == ["tld_variants_parked"]
    assert by_domain["www.acmepay.com.br"].confidence == 0.15
    assert by_domain["aspmx.l.google.com"].category == "terceiros"
    assert raw.context["analytics"]["trackers"]["google_analytics_ga4"] == ["G-ACME12345"]
