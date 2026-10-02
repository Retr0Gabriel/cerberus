"""Analisador para qualquer API no padrão da OpenAI (`/v1/chat/completions`).

Cobre o Ollama rodando local (grátis, padrão `http://localhost:11434/v1`) e
provedores com plano gratuito compatíveis com esse padrão. Como esses modelos
não usam a ferramenta forçada do Claude, o pedido é por JSON puro, validado
com o mesmo schema Pydantic (`LLMVerdict`).

Pensado para modelos pequenos (~3B): os candidatos vão em lotes, um lote com
JSON inválido é tentado de novo uma vez, a falha de um lote não descarta os
demais e, por padrão, `Guardrails` impede o modelo de descartar evidência forte
ou mexer demais nas notas.
"""

from __future__ import annotations

from typing import Any

import httpx

from core.http_client import HttpClient
from core.llm import Guardrails, LLMAnalysisError, build_json_request, parse_verdict_text
from models import DomainMatch, FalsePositive, LLMDomainVerdict, LLMVerdict, RawData

DEFAULT_BASE_URL = "http://localhost:11434/v1"  # Ollama
DEFAULT_MODEL = "qwen2.5:3b"
DEFAULT_BATCH_SIZE = 15
DEFAULT_TIMEOUT = 600.0  # em CPU/GPU modesta, um lote pode levar minutos


class OpenAICompatAnalyzer:
    name = "openai"

    def __init__(
        self,
        http: HttpClient,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        timeout: float = DEFAULT_TIMEOUT,
        attempts_per_batch: int = 2,
        guardrails: Guardrails | None = Guardrails(),  # noqa: B008 (imutável)
    ) -> None:
        self.http = http
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.batch_size = max(1, batch_size)
        self.timeout = timeout
        self.attempts_per_batch = max(1, attempts_per_batch)
        self.guardrails = guardrails

    async def _complete(self, system: str, user: str) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else None
        body: dict[str, Any] = {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            resp = await self.http.request(
                "POST",
                f"{self.base_url}/chat/completions",
                json=body,
                headers=headers,
                request_timeout=self.timeout,
            )
            return str(resp.json()["choices"][0]["message"]["content"])
        except httpx.HTTPError as exc:
            raise LLMAnalysisError(f"falha no modelo em {self.base_url}: {exc}") from exc
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMAnalysisError(f"resposta inesperada de {self.base_url}: {exc}") from exc

    async def _review_batch(self, raw: RawData, batch: list[DomainMatch]) -> LLMVerdict:
        system, user = build_json_request(raw, batch)
        last: LLMAnalysisError | None = None
        for _ in range(self.attempts_per_batch):
            try:
                return parse_verdict_text(await self._complete(system, user))
            except LLMAnalysisError as exc:
                last = exc
        assert last is not None
        raise last

    async def review(self, raw: RawData, candidates: list[DomainMatch]) -> LLMVerdict:
        batches = [
            candidates[i : i + self.batch_size] for i in range(0, len(candidates), self.batch_size)
        ]
        matches: list[LLMDomainVerdict] = []
        false_positives: list[FalsePositive] = []
        summaries: list[str] = []
        errors: list[str] = []
        # em sequência: um modelo local não ganha nada com pedidos simultâneos
        for batch in batches:
            try:
                verdict = await self._review_batch(raw, batch)
            except LLMAnalysisError as exc:
                errors.append(str(exc))
                continue
            matches += verdict.matches
            false_positives += verdict.false_positives
            if verdict.summary.strip():
                summaries.append(verdict.summary.strip())

        if len(errors) == len(batches):
            raise LLMAnalysisError(f"todos os {len(batches)} lote(s) falharam: {errors[0]}")
        summary = " ".join(summaries)
        if errors:
            summary += (
                f" [{len(errors)} de {len(batches)} lotes falharam; esses candidatos ficaram"
                " com a classificação heurística]"
            )
        return LLMVerdict(summary=summary, matches=matches, false_positives=false_positives)
