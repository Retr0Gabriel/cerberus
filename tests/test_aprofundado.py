"""Regressões da rodada de testes aprofundados (injeção, limites, cobertura)."""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path

import httpx
import pytest
import respx
from rich.console import Console
from typer.testing import CliRunner

from cli.app import app
from cli.render import render_report
from collectors.base import Collector
from collectors.certspotter import CertSpotterCollector
from collectors.crtsh import CrtShCollector
from collectors.wayback import WaybackCollector
from core.http_client import HttpClient
from core.pipeline import analyze, collect_all
from core.traffic import TrafficRecorder
from core.whois43 import Whois43Client, WhoisError
from models import AnalysisReport, Collected, DomainMatch, FalsePositive, Finding, LLMVerdict
from tests.conftest import ACME_FIXTURE

runner = CliRunner()
REPLAY = ["--replay", str(ACME_FIXTURE), "--no-llm", "--no-banner"]
ESC = "\x1b"


# --- injeção no terminal -------------------------------------------------------

HOSTILE = [
    "texto [/] quebrado",
    "[link=https://phishing.test]clique[/link]",
    "[bold red blink]ALERTA FALSO[/]",
    "limpa\x1b[2Ja tela",
    "título\x1b]0;janela\x07da janela",
    "inverte‮texto",
]


@pytest.mark.parametrize("payload", HOSTILE)
def test_report_never_lets_external_text_control_the_terminal(payload: str) -> None:
    report = AnalysisReport(
        target="alvo.com",
        analyzer="openai",
        model=payload,
        summary=payload,
        matches=[
            DomainMatch(
                domain="x.com",
                registered_domain="x.com",
                category="relacionado",
                confidence=0.5,
                reasoning=payload,
                evidence=[payload],
            )
        ],
        false_positives=[FalsePositive(domain="y.com", reason=payload)],
        collector_errors={"wayback": payload},
        warnings=[payload],
    )
    buf = io.StringIO()
    console = Console(file=buf, width=300, force_terminal=True, color_system="truecolor")
    render_report(report, console, verbose=True)  # não pode levantar MarkupError
    out = buf.getvalue()
    assert "\x1b[2J" not in out and "\x1b]" not in out and "‮" not in out
    if payload.startswith(("texto", "[")):  # marcação do Rich aparece como texto literal
        assert payload.split("]")[0] + "]" in out


def test_traffic_show_strips_escape_sequences_from_server_data(tmp_path: Path) -> None:
    entry = {
        "startedDateTime": "2026-01-01T00:00:00+00:00",
        "time": 1.0,
        "request": {"method": "GET", "url": "https://alvo.test/", "httpVersion": "HTTP/1.1",
                    "headers": []},
        "response": {
            "status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
            "headers": [{"name": "x-evil", "value": "a\x1b]0;hackeado\x07b"}],
            "content": {"size": 3, "mimeType": "text/html\x1b[2J", "text": "x\x1b[2Jy [/]"},
        },
    }  # fmt: skip
    har = tmp_path / "evil.har"
    har.write_text(json.dumps({"log": {"entries": [entry]}}), encoding="utf-8")
    for args in (["traffic", str(har)], ["traffic", str(har), "--show", "1"]):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, result.output
        assert ESC not in result.output


def test_domain_argument_with_markup_gives_friendly_error() -> None:
    result = runner.invoke(app, ["analyze", "[/]", "--no-llm"])
    assert result.exit_code == 2
    assert "domínio inválido" in result.output


def test_apply_verdict_with_corrupted_report(tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    report.write_text('{"target": 1}', encoding="utf-8")
    answer = tmp_path / "a.txt"
    answer.write_text("{}", encoding="utf-8")
    result = runner.invoke(app, ["apply-verdict", str(report), str(answer)])
    assert result.exit_code == 2
    assert "não é um relatório do Cerberus válido" in " ".join(result.output.split())


# --- limites: nada pode ser cortado em silêncio ---------------------------------


def many_matches(n: int) -> list[DomainMatch]:
    return [
        DomainMatch(
            domain=f"d{i}.com", registered_domain=f"d{i}.com", category="relacionado",
            confidence=0.5,
        )
        for i in range(n)
    ]  # fmt: skip


def test_table_rows_are_capped_on_screen_but_not_in_files(tmp_path: Path) -> None:
    report = AnalysisReport(target="x.com", analyzer="heuristica", matches=many_matches(250))
    buf = io.StringIO()
    render_report(report, Console(file=buf, width=200, color_system=None), max_rows=200)
    assert "… e mais 50" in buf.getvalue()
    assert "d249.com" not in buf.getvalue()

    buf = io.StringIO()
    render_report(report, Console(file=buf, width=200, color_system=None), max_rows=None)
    assert "d249.com" in buf.getvalue()


def test_output_file_in_table_format_has_everything_and_no_banner(tmp_path: Path) -> None:
    out = tmp_path / "relatorio.txt"
    result = runner.invoke(
        app, ["analyze", "acmecorp.com.br", *REPLAY[:-1], "--max-rows", "1", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "acmestore.com" in text and "e mais" not in text  # completo apesar de --max-rows 1
    assert "C E R B E R U S" not in text


class CountingAnalyzer:
    name = "openai"
    model = "fake"
    guardrails = None

    def __init__(self) -> None:
        self.received = 0

    async def review(self, raw, candidates):  # type: ignore[no-untyped-def]
        self.received = len(candidates)
        return LLMVerdict(summary="ok", matches=[], false_positives=[])


class ManyFindings(Collector):
    name = "dns"

    async def collect(self, target: str) -> Collected:
        return Collected(
            findings=[Finding(domain=f"marca{i}.com", source="dns") for i in range(50)]
        )


async def test_review_limit_applies_and_warns(http: HttpClient) -> None:
    analyzer = CountingAnalyzer()
    report = await analyze("alvo.com", [ManyFindings(http)], analyzer, max_review=10)
    assert analyzer.received == 10
    assert any("40 candidatos não foram revisados" in w for w in report.warnings)


async def test_certspotter_warns_when_page_limit_is_hit(
    respx_router: respx.MockRouter, http: HttpClient
) -> None:
    respx_router.get("https://api.certspotter.com/v1/issuances").respond(
        json=[{"id": "1", "dns_names": ["a.alvo.com"]}]
    )
    result = await CertSpotterCollector(http, max_pages=2).run("alvo.com")
    assert "limite de 2 páginas" in result.metadata["truncated"]


async def test_wayback_warns_when_url_limit_is_hit(
    respx_router: respx.MockRouter, http: HttpClient
) -> None:
    rows = [["original"]] + [[f"http://h{i}.alvo.com/"] for i in range(3)]
    respx_router.get("https://web.archive.org/cdx/search/cdx").respond(json=rows)
    result = await WaybackCollector(http, limit=3).run("alvo.com")
    assert "limite de 3 URLs" in result.metadata["truncated"]


async def test_truncation_reaches_report_warnings(
    respx_router: respx.MockRouter, http: HttpClient
) -> None:
    rows = [["original"]] + [[f"http://h{i}.alvo.com/"] for i in range(2)]
    respx_router.get("https://web.archive.org/cdx/search/cdx").respond(json=rows)
    report = await analyze("alvo.com", [WaybackCollector(http, limit=2)])
    assert any(w.startswith("wayback: limite de 2 URLs") for w in report.warnings)


# --- falhas de formato e caminhos sem cobertura ---------------------------------


async def test_unexpected_json_shape_is_caught_by_collector(
    respx_router: respx.MockRouter, http: HttpClient
) -> None:
    respx_router.get("https://crt.sh/").respond(json=["texto", "em vez de", "objetos"])
    result = await CrtShCollector(http).run("alvo.com")
    assert not result.ok
    assert result.error.startswith("AttributeError")  # type: ignore[union-attr]


class Exploding(Collector):
    name = "bugado"

    async def collect(self, target: str) -> Collected:
        raise RuntimeError("bug inesperado")


async def test_unexpected_exception_does_not_stop_the_analysis(http: HttpClient) -> None:
    raw = await collect_all([Exploding(http)], "alvo.com")
    assert raw.results[0].error == "RuntimeError: bug inesperado"


async def test_whois_server_that_never_answers_times_out() -> None:
    async def silent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # nunca responde; termina quando o cliente desiste e fecha a conexão (sem isso,
        # o Python 3.12 espera a conexão fechar ao encerrar o servidor e o teste trava)
        await reader.read()
        writer.close()

    server = await asyncio.start_server(silent, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        with pytest.raises(WhoisError, match="sem resposta"):
            await Whois43Client(timeout=0.3, port=port).query("127.0.0.1", "x.me")


async def test_har_records_post_body(respx_router: respx.MockRouter) -> None:
    respx_router.post("https://api.test/v1/chat").respond(json={"ok": True})
    recorder = TrafficRecorder()
    async with HttpClient(retries=0, event_hooks=recorder.hooks) as http:
        await http.request("POST", "https://api.test/v1/chat", json={"prompt": "oi"})
    assert json.loads(recorder.entries[0]["request"]["postData"]["text"]) == {"prompt": "oi"}


def test_replay_from_har_command_round_trip(tmp_path: Path) -> None:
    har = tmp_path / "t.har"
    first = runner.invoke(app, ["analyze", "acmecorp.com.br", *REPLAY, "-f", "json",
                                "--har", str(har)])  # fmt: skip
    assert first.exit_code == 0, first.output
    fixture = tmp_path / "novo" / "replay.json"
    conv = runner.invoke(app, ["replay-from-har", str(har), str(fixture)])
    assert conv.exit_code == 0, conv.output
    again = runner.invoke(
        app, ["analyze", "acmecorp.com.br", "--replay", str(fixture), "--no-llm", "-f", "json"]
    )
    assert again.exit_code == 0, again.output
    assert len(json.loads(again.output)["matches"]) == 20  # mesmo resultado do original


def test_auto_mode_without_ai_explains_the_free_options() -> None:
    result = runner.invoke(
        app, ["analyze", "acmecorp.com.br", "--replay", str(ACME_FIXTURE),
              "-f", "json", "--llm", "auto"]
    )  # fmt: skip
    # com --replay o auto escolhe o Claude simulado; sem replay e sem chaves, avisa
    assert result.exit_code in (0, 1)
    plain = runner.invoke(app, ["analyze", "x..", "--llm", "auto"])
    assert plain.exit_code == 2  # domínio inválido, mas o aviso vem antes
    assert "Alternativas grátis" in plain.output


def test_network_failure_message_names_the_host() -> None:
    from collectors.base import describe_error

    exc = httpx.ReadError("", request=httpx.Request("GET", "https://web.archive.org/x"))
    assert "web.archive.org" in describe_error(exc)
