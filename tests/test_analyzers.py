from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from typer.testing import CliRunner

from cli.app import app
from core.http_client import HttpClient
from core.llm import LLMAnalysisError, parse_verdict_text
from core.openai_compat import OpenAICompatAnalyzer
from models import AnalysisReport, DomainMatch, RawData
from tests.conftest import ACME_FIXTURE

runner = CliRunner()
OLLAMA = "http://localhost:11434/v1/chat/completions"
VERDICT = {
    "summary": "ok",
    "matches": [
        {"domain": "a.com", "category": "relacionado", "confidence": 0.9, "reasoning": "r"}
    ],
    "false_positives": [],
}


# --- parse_verdict_text ------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        json.dumps(VERDICT),
        "```json\n" + json.dumps(VERDICT) + "\n```",
        "Claro! Aqui está a análise:\n" + json.dumps(VERDICT) + "\nEspero ter ajudado.",
    ],
)
def test_parse_verdict_text_tolerates_wrappers(text: str) -> None:
    assert parse_verdict_text(text).matches[0].domain == "a.com"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("não sei", "não contém um objeto JSON"),
        ('{"summary": "x",}', "JSON inválido"),
        ('{"summary": "x", "matches": [{"domain": "a.com"}], "false_positives": []}', "schema"),
    ],
)
def test_parse_verdict_text_rejects_bad_answers(text: str, message: str) -> None:
    with pytest.raises(LLMAnalysisError, match=message):
        parse_verdict_text(text)


# --- OpenAICompatAnalyzer ----------------------------------------------------


def chat_answer(content: str) -> dict[str, Any]:
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


def candidates(n: int) -> list[DomainMatch]:
    return [
        DomainMatch(
            domain=f"d{i}.com",
            registered_domain=f"d{i}.com",
            category="relacionado",
            confidence=0.3,
        )
        for i in range(n)
    ]


def verdict_for(request: httpx.Request) -> dict[str, Any]:
    """Responde aprovando exatamente os domínios que vieram no lote."""
    user = json.loads(request.content)["messages"][1]["content"]
    payload = json.loads(user.split("\n", 1)[1])
    return {
        "summary": f"{len(payload['candidates'])} avaliados",
        "matches": [
            {"domain": c["domain"], "category": "relacionado", "confidence": 0.8, "reasoning": "r"}
            for c in payload["candidates"]
        ],
        "false_positives": [],
    }


async def test_openai_compat_batches_and_sends_json_mode(
    respx_router: respx.MockRouter, http: HttpClient
):
    route = respx_router.post(OLLAMA).mock(
        side_effect=lambda req: httpx.Response(200, json=chat_answer(json.dumps(verdict_for(req))))
    )
    analyzer = OpenAICompatAnalyzer(http, model="qwen2.5:3b", batch_size=4)
    verdict = await analyzer.review(RawData(target="x.com", results=[]), candidates(10))

    assert route.call_count == 3  # 4 + 4 + 2
    body = json.loads(route.calls[0].request.content)
    assert body["model"] == "qwen2.5:3b"
    assert body["response_format"] == {"type": "json_object"}
    assert "authorization" not in route.calls[0].request.headers  # Ollama não usa chave
    assert {m.domain for m in verdict.matches} == {f"d{i}.com" for i in range(10)}
    assert verdict.summary == "4 avaliados 4 avaliados 2 avaliados"


async def test_openai_compat_retries_malformed_json_once(
    respx_router: respx.MockRouter, http: HttpClient
):
    route = respx_router.post(OLLAMA).mock(
        side_effect=[
            httpx.Response(200, json=chat_answer("isto não é JSON")),
            httpx.Response(200, json=chat_answer(json.dumps(VERDICT))),
        ]
    )
    verdict = await OpenAICompatAnalyzer(http).review(
        RawData(target="x.com", results=[]), candidates(1)
    )
    assert route.call_count == 2
    assert verdict.summary == "ok"


async def test_openai_compat_keeps_good_batches_when_one_fails(
    respx_router: respx.MockRouter, http: HttpClient
):
    respx_router.post(OLLAMA).mock(
        side_effect=[
            httpx.Response(200, json=chat_answer(json.dumps(VERDICT))),
            httpx.Response(200, json=chat_answer("lixo")),
            httpx.Response(200, json=chat_answer("lixo de novo")),
        ]
    )
    analyzer = OpenAICompatAnalyzer(http, batch_size=1, api_key="chave-remota")
    verdict = await analyzer.review(RawData(target="x.com", results=[]), candidates(2))
    assert [m.domain for m in verdict.matches] == ["a.com"]
    assert "1 de 2 lotes falharam" in verdict.summary


async def test_openai_compat_all_batches_failing_raises(
    respx_router: respx.MockRouter, http: HttpClient
):
    respx_router.post(OLLAMA).mock(side_effect=httpx.ConnectError("Ollama desligado"))
    with pytest.raises(LLMAnalysisError, match="todos os 1 lote"):
        await OpenAICompatAnalyzer(http).review(RawData(target="x.com", results=[]), candidates(1))


# --- modo manual de ponta a ponta (CLI) --------------------------------------


def test_manual_mode_round_trip(tmp_path: Path) -> None:
    replay = str(ACME_FIXTURE)
    first = runner.invoke(
        app,
        [
            "analyze",
            "acmecorp.com.br",
            "--replay",
            replay,
            "--llm",
            "manual",
            "--manual-dir",
            str(tmp_path),
        ],
    )
    assert first.exit_code == 0, first.output
    prompt = (tmp_path / "revisao-acmecorp.com.br.prompt.txt").read_text(encoding="utf-8")
    report_file = tmp_path / "revisao-acmecorp.com.br.relatorio.json"
    assert "Responda APENAS com um objeto JSON" in prompt
    assert '"domain": "acmecorp.net"' in prompt
    assert "apply-verdict" in first.output

    # o "chat" responde em markdown, como costuma fazer
    answer = tmp_path / "resposta.txt"
    answer.write_text(
        "Aqui está:\n```json\n"
        + json.dumps(
            {
                "summary": "O dono é a Acme Corp.",
                "matches": [
                    {
                        "domain": "acmestore.com",
                        "category": "relacionado",
                        "confidence": 0.95,
                        "reasoning": "Mesmo certificado do alvo.",
                    }
                ],
                "false_positives": [{"domain": "acmecorp.net", "reason": "Estacionado."}],
            }
        )
        + "\n```",
        encoding="utf-8",
    )
    out = tmp_path / "final.json"
    second = runner.invoke(
        app,
        [
            "apply-verdict",
            str(report_file),
            str(answer),
            "--model",
            "claude.ai",
            "-f",
            "json",
            "-o",
            str(out),
        ],
    )
    assert second.exit_code == 0, second.output
    final = AnalysisReport.model_validate_json(out.read_text(encoding="utf-8"))
    assert final.analyzer == "manual"
    assert final.model == "claude.ai"
    assert final.summary == "O dono é a Acme Corp."
    assert {fp.domain for fp in final.false_positives} == {"acmecorp.net"}
    by_domain = {m.domain: m for m in final.matches}
    assert by_domain["acmestore.com"].confidence == 0.95
    assert by_domain["acmedns.com.br"].reasoning == "não avaliado pelo modelo"
    assert not any(w.startswith("modo manual:") for w in final.warnings)


def test_apply_verdict_rejects_answer_without_json(tmp_path: Path) -> None:
    report_file = tmp_path / "r.json"
    report_file.write_text(
        AnalysisReport(target="x.com", analyzer="heuristica", matches=[]).model_dump_json(),
        encoding="utf-8",
    )
    answer = tmp_path / "a.txt"
    answer.write_text("Desculpe, não posso ajudar.", encoding="utf-8")
    result = runner.invoke(app, ["apply-verdict", str(report_file), str(answer)])
    assert result.exit_code == 2
    assert "não contém um objeto JSON" in result.output


def test_openai_mode_with_replay_calls_the_real_model_endpoint(
    respx_router: respx.MockRouter, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Fontes vêm do arquivo de replay, mas o modelo local é chamado de verdade."""
    monkeypatch.setenv("CERBERUS_LLM_BASE_URL", "http://localhost:11434/v1")
    route = respx_router.post(OLLAMA).mock(
        side_effect=lambda req: httpx.Response(200, json=chat_answer(json.dumps(verdict_for(req))))
    )
    out = tmp_path / "r.json"
    result = runner.invoke(
        app,
        [
            "analyze",
            "acmecorp.com.br",
            "--replay",
            str(ACME_FIXTURE),
            "--llm",
            "openai",
            "-f",
            "json",
            "-o",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert route.called
    report = AnalysisReport.model_validate_json(out.read_text(encoding="utf-8"))
    assert report.analyzer == "openai"
    assert report.model == "qwen2.5:3b"


def test_guardrails_protect_strong_evidence_and_limit_shifts() -> None:
    """Reproduz erros reais de um modelo pequeno (qwen2.5:3b)."""
    from core.llm import Guardrails
    from core.pipeline import apply_verdict
    from models import LLMVerdict

    def cand(domain: str, confidence: float, category: str = "relacionado") -> DomainMatch:
        return DomainMatch(
            domain=domain, registered_domain=domain, category=category, confidence=confidence
        )

    candidates = [
        cand("ns1.acmedns.net", 0.6),  # nameserver do alvo: evidência forte
        cand("acmelab.com", 0.2),  # outro TLD, outro dono: evidência fraca
        cand("transition.fcc.gov", 0.15),  # link solto na home
    ]
    verdict = LLMVerdict(
        summary="s",
        matches=[
            {
                "domain": "acmelab.com",
                "category": "relacionado",
                "confidence": 1.0,
                "reasoning": "certificado compartilhado (inventado)",
            }
        ],
        false_positives=[
            {"domain": "ns1.acmedns.net", "reason": "TLD .me não publica RDAP"},
            {"domain": "transition.fcc.gov", "reason": "link sem relação"},
        ],
    )
    kept, rejected = apply_verdict(candidates, verdict, Guardrails())
    by_domain = {m.domain: m for m in kept}
    assert "mantido por evidência forte" in by_domain["ns1.acmedns.net"].reasoning
    assert by_domain["acmelab.com"].confidence == 0.35  # 0.2 + 0.15, não 1.0
    assert [fp.domain for fp in rejected] == ["transition.fcc.gov"]  # ruído fraco sai

    # sem limites (Claude / manual), o veredito é aplicado como veio
    kept, rejected = apply_verdict(candidates, verdict)
    assert {fp.domain for fp in rejected} == {"ns1.acmedns.net", "transition.fcc.gov"}
    assert {m.domain: m for m in kept}["acmelab.com"].confidence == 1.0
