"""Correlação analítica com um modelo de linguagem.

`Analyzer` é o contrato que o pipeline usa; há três implementações:
- `ClaudeAnalyzer` (aqui): API do Claude, saída estruturada garantida forçando
  uma ferramenta cujo `input_schema` é o schema Pydantic de `LLMVerdict`;
- `OpenAICompatAnalyzer` (core/openai_compat.py): Ollama local ou qualquer API
  no padrão da OpenAI, pedindo JSON puro;
- modo manual (cli): o prompt vai para um chat e a resposta volta por arquivo.
Em todos os casos o conteúdo é validado com Pydantic antes de ser usado.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import anthropic
import httpx
import httpx2
from anthropic import AsyncAnthropic
from pydantic import ValidationError

from core.prompts import JSON_SYSTEM_PROMPT, SYSTEM_PROMPT
from models import DomainMatch, LLMVerdict, RawData

# a chamada ao Claude pode levar minutos; o timeout fino fica a cargo do SDK
BRIDGE_TIMEOUT = httpx.Timeout(600.0)
TOOL_NAME = "submit_analysis"
MAX_CANDIDATES = 300
MAX_EVIDENCE_PER_CANDIDATE = 4


class LLMAnalysisError(RuntimeError):
    pass


@dataclass(frozen=True)
class Guardrails:
    """Limites para modelos pequenos (ex.: 3B local), que erram com confiança.

    - `protect_from`: candidatos com confiança heurística >= este valor não podem
      ser descartados como falso positivo (a sugestão fica registrada no motivo);
    - `max_shift`: o modelo só move a confiança até ± este valor.
    Em teste real (qwen2.5:3b), sem limites o modelo descartou
    os nameservers do próprio alvo e inventou "certificado compartilhado".
    """

    protect_from: float = 0.5
    max_shift: float = 0.15


class Analyzer(Protocol):
    """O que o pipeline precisa de um analisador: nome, modelo, limites e a revisão."""

    # propriedades somente leitura: aceitam implementações com tipos mais estreitos
    @property
    def name(self) -> str: ...
    @property
    def model(self) -> str | None: ...
    @property
    def guardrails(self) -> Guardrails | None: ...

    async def review(self, raw: RawData, candidates: list[DomainMatch]) -> LLMVerdict: ...


_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def parse_verdict_text(text: str) -> LLMVerdict:
    """Extrai e valida o JSON de uma resposta em texto livre.

    Tolera blocos ```json```, texto antes/depois do objeto e espaços. Levanta
    `LLMAnalysisError` se não houver JSON válido no formato de `LLMVerdict`.
    """
    fenced = _FENCE_RE.search(text)
    body = fenced.group(1) if fenced else text
    start, end = body.find("{"), body.rfind("}")
    if start == -1 or end <= start:
        raise LLMAnalysisError("a resposta não contém um objeto JSON")
    try:
        data = json.loads(body[start : end + 1])
    except ValueError as exc:
        raise LLMAnalysisError(f"JSON inválido na resposta: {exc}") from exc
    try:
        return LLMVerdict.model_validate(data)
    except ValidationError as exc:
        raise LLMAnalysisError(f"resposta fora do schema: {exc}") from exc


class HttpxBridgeTransport(httpx2.AsyncBaseTransport):
    """Encaminha as requisições do SDK anthropic (que usa httpx2) para um
    `httpx.AsyncClient`. Usado apenas no modo --replay e nos testes, para que as
    chamadas ao Claude passem pelo mesmo transporte offline / respx dos coletores."""

    _SKIP_HEADERS = frozenset({"content-encoding", "content-length", "transfer-encoding"})

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        resp = await self.client.request(
            request.method,
            str(request.url),
            headers=request.headers.multi_items(),
            content=await request.aread(),
        )
        headers = [(k, v) for k, v in resp.headers.multi_items() if k not in self._SKIP_HEADERS]
        return httpx2.Response(
            resp.status_code, headers=headers, content=resp.content, request=request
        )

    async def aclose(self) -> None:
        await self.client.aclose()


def create_anthropic_client(
    api_key: str,
    transport: httpx.AsyncBaseTransport | None = None,
    max_retries: int = 2,
    event_hooks: Mapping[str, list[Any]] | None = None,
) -> AsyncAnthropic:
    """Cliente do Claude. Com `transport` (httpx), todo o tráfego passa por ele;
    com `event_hooks`, o tráfego passa por um `httpx.AsyncClient` que os executa
    (usado para gravar a chamada no HAR)."""
    if transport is None and not event_hooks:
        return AsyncAnthropic(api_key=api_key, max_retries=max_retries)
    inner = httpx.AsyncClient(
        transport=transport, event_hooks=dict(event_hooks or {}), timeout=BRIDGE_TIMEOUT
    )
    bridge = HttpxBridgeTransport(inner)
    return AsyncAnthropic(
        api_key=api_key,
        max_retries=max_retries,
        http_client=httpx2.AsyncClient(transport=bridge),
    )


def inline_refs(schema: dict[str, Any]) -> dict[str, Any]:
    """Resolve `$ref`/`$defs` do JSON Schema do Pydantic em um schema autocontido."""
    defs: dict[str, Any] = schema.get("$defs", {})

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/$defs/"):
                return resolve(defs[ref.removeprefix("#/$defs/")])
            return {k: resolve(v) for k, v in node.items() if k != "$defs"}
        if isinstance(node, list):
            return [resolve(v) for v in node]
        return node

    resolved: dict[str, Any] = resolve(schema)
    return resolved


ANALYSIS_TOOL: dict[str, Any] = {
    "name": TOOL_NAME,
    "description": "Registra a análise de correlação dos domínios candidatos.",
    "input_schema": inline_refs(LLMVerdict.model_json_schema()),
}


def build_payload(raw: RawData, candidates: list[DomainMatch]) -> dict[str, Any]:
    return {
        "target": raw.target,
        "candidates": [
            {
                "domain": c.domain,
                "heuristic_category": c.category,
                "sources": c.sources,
                "evidence": c.evidence[:MAX_EVIDENCE_PER_CANDIDATE],
            }
            for c in candidates[:MAX_CANDIDATES]
        ],
        "context": raw.context,
        "collector_errors": raw.errors,
    }


def build_json_request(raw: RawData, candidates: list[DomainMatch]) -> tuple[str, str]:
    """(system, user) pedindo JSON puro: para modelos sem ferramenta e para o chat manual."""
    payload = build_payload(raw, candidates)
    user = "Dados coletados (JSON):\n" + json.dumps(payload, ensure_ascii=False, indent=1)
    return JSON_SYSTEM_PROMPT, user


def build_manual_prompt(raw: RawData, candidates: list[DomainMatch]) -> str:
    """Texto único para colar em um chat (claude.ai ou outro)."""
    system, user = build_json_request(raw, candidates)
    return f"{system}\n{user}\n"


class ClaudeAnalyzer:
    name = "claude"
    guardrails: Guardrails | None = None  # modelo forte: confiança total

    def __init__(self, client: AsyncAnthropic, model: str, max_tokens: int = 16000) -> None:
        self.client = client
        self.model = model
        self.max_tokens = max_tokens

    async def review(self, raw: RawData, candidates: list[DomainMatch]) -> LLMVerdict:
        """Envia os candidatos ao Claude e devolve o veredito validado.

        Levanta `LLMAnalysisError` em falha da API ou resposta fora do schema.
        """
        payload = build_payload(raw, candidates)
        try:
            message = await self.client.messages.create(  # type: ignore[call-overload]
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                tools=[ANALYSIS_TOOL],
                tool_choice={"type": "tool", "name": TOOL_NAME},
                messages=[
                    {
                        "role": "user",
                        "content": "Dados coletados (JSON):\n"
                        + json.dumps(payload, ensure_ascii=False, indent=1),
                    }
                ],
            )
        except anthropic.APIError as exc:
            raise LLMAnalysisError(f"falha na API do Claude: {exc}") from exc

        if message.stop_reason == "max_tokens":
            raise LLMAnalysisError("resposta do Claude truncada (max_tokens)")
        for block in message.content:
            if block.type == "tool_use" and block.name == TOOL_NAME:
                try:
                    return LLMVerdict.model_validate(block.input)
                except ValidationError as exc:
                    raise LLMAnalysisError(f"resposta do Claude fora do schema: {exc}") from exc
        raise LLMAnalysisError("o Claude não retornou a análise estruturada")
