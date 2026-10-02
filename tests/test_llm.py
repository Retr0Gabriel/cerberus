from __future__ import annotations

import json
from collections.abc import AsyncIterator

import anthropic
import httpx
import pytest
import respx
from anthropic import AsyncAnthropic

from core.llm import (
    ANALYSIS_TOOL,
    TOOL_NAME,
    ClaudeAnalyzer,
    LLMAnalysisError,
    create_anthropic_client,
)
from core.pipeline import apply_verdict
from models import CollectorResult, DomainMatch, Finding, LLMVerdict, RawData
from tests.conftest import ANTHROPIC_MESSAGES_URL, claude_tool_message

RAW = RawData(
    target="acme.com",
    results=[
        CollectorResult(
            name="crtsh",
            findings=[Finding(domain="acmepay.com", source="crtsh_org", evidence="O=Acme")],
            metadata={"org": "Acme"},
        ),
        CollectorResult(name="wayback", error="HTTPStatusError: 503"),
    ],
)


def match(domain: str, category: str = "relacionado", confidence: float = 0.5) -> DomainMatch:
    return DomainMatch.model_validate(
        {
            "domain": domain,
            "registered_domain": domain,
            "category": category,
            "confidence": confidence,
            "sources": ["crtsh"],
        }
    )


VALID_INPUT = {
    "summary": "Resumo.",
    "matches": [
        {
            "domain": "acmepay.com",
            "category": "relacionado",
            "confidence": 0.9,
            "reasoning": "O=Acme",
        }
    ],
    "false_positives": [{"domain": "acme.net", "reason": "estacionado"}],
}


@pytest.fixture
async def analyzer() -> AsyncIterator[ClaudeAnalyzer]:
    # transporte httpx padrão: interceptado pelo respx
    client = create_anthropic_client(
        "chave-falsa-de-teste", transport=httpx.AsyncHTTPTransport(), max_retries=0
    )
    async with client:
        yield ClaudeAnalyzer(client, model="claude-opus-5-5")


async def test_default_client_is_blocked_in_tests() -> None:
    async with AsyncAnthropic(api_key="x", max_retries=0) as client:
        with pytest.raises(anthropic.APIConnectionError) as exc_info:
            await client.messages.create(
                model="claude-opus-5-5",
                max_tokens=10,
                messages=[{"role": "user", "content": "oi"}],
            )
    assert "rede real bloqueada" in str(exc_info.value.__cause__)


def test_tool_schema_is_self_contained() -> None:
    dumped = json.dumps(ANALYSIS_TOOL["input_schema"])
    assert "$ref" not in dumped and "$defs" not in dumped
    assert set(ANALYSIS_TOOL["input_schema"]["required"]) == {
        "summary",
        "matches",
        "false_positives",
    }


async def test_review_forces_structured_output(
    respx_router: respx.MockRouter, analyzer: ClaudeAnalyzer
):
    route = respx_router.post(ANTHROPIC_MESSAGES_URL).respond(json=claude_tool_message(VALID_INPUT))
    verdict = await analyzer.review(RAW, [match("acmepay.com"), match("acme.net")])

    assert verdict == LLMVerdict.model_validate(VALID_INPUT)
    body = json.loads(route.calls.last.request.content)
    assert body["model"] == "claude-opus-5-5"
    assert body["tool_choice"] == {"type": "tool", "name": TOOL_NAME}
    user_payload = body["messages"][0]["content"]
    assert "acmepay.com" in user_payload and "acme.net" in user_payload
    assert "HTTPStatusError: 503" in user_payload  # erros dos coletores vão como contexto


async def test_review_rejects_output_outside_schema(
    respx_router: respx.MockRouter, analyzer: ClaudeAnalyzer
):
    bad = {**VALID_INPUT, "matches": [{"domain": "x.com", "category": "talvez", "confidence": 3}]}
    respx_router.post(ANTHROPIC_MESSAGES_URL).respond(json=claude_tool_message(bad))
    with pytest.raises(LLMAnalysisError, match="fora do schema"):
        await analyzer.review(RAW, [match("x.com")])


async def test_review_without_tool_call(respx_router: respx.MockRouter, analyzer: ClaudeAnalyzer):
    msg = claude_tool_message(VALID_INPUT)
    msg["content"] = [{"type": "text", "text": "não vou usar a ferramenta"}]
    msg["stop_reason"] = "end_turn"
    respx_router.post(ANTHROPIC_MESSAGES_URL).respond(json=msg)
    with pytest.raises(LLMAnalysisError, match="não retornou"):
        await analyzer.review(RAW, [match("x.com")])


async def test_review_api_error(respx_router: respx.MockRouter, analyzer: ClaudeAnalyzer):
    respx_router.post(ANTHROPIC_MESSAGES_URL).respond(
        529, json={"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}
    )
    with pytest.raises(LLMAnalysisError, match="falha na API"):
        await analyzer.review(RAW, [match("x.com")])


def test_apply_verdict_guards_against_hallucination_and_reclassification() -> None:
    candidates = [
        match("acme.com", "alvo", 0.9),
        match("api.acme.com", "subdominio", 0.7),
        match("acmepay.com"),
        match("acme.net"),
        match("naoavaliado.com"),
    ]
    verdict = LLMVerdict.model_validate(
        {
            "summary": "s",
            "matches": [
                {
                    "domain": "acmepay.com",
                    "category": "relacionado",
                    "confidence": 0.95,
                    "reasoning": "r",
                },
                {
                    "domain": "inventado.com",
                    "category": "relacionado",
                    "confidence": 1,
                    "reasoning": "r",
                },
                {
                    "domain": "api.acme.com",
                    "category": "terceiros",
                    "confidence": 0.1,
                    "reasoning": "r",
                },
            ],
            "false_positives": [
                {"domain": "acme.net", "reason": "estacionado"},
                {"domain": "acme.com", "reason": "o modelo não pode descartar o alvo"},
            ],
        }
    )
    kept, rejected = apply_verdict(candidates, verdict)
    by_domain = {m.domain: m for m in kept}

    assert "inventado.com" not in by_domain
    assert [fp.domain for fp in rejected] == ["acme.net"]
    assert by_domain["acme.com"].category == "alvo"
    assert by_domain["api.acme.com"].category == "subdominio"
    assert by_domain["acmepay.com"].confidence == 0.95
    assert by_domain["naoavaliado.com"].reasoning == "não avaliado pelo modelo"
