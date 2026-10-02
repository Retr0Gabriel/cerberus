"""Resultado da análise: domínios correlacionados e falsos positivos descartados."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field, computed_field

Category = Literal["alvo", "subdominio", "relacionado", "terceiros"]
# quem fez a revisão final: um modelo (claude, openai = API compatível/Ollama,
# manual = resposta colada de um chat) ou só a heurística
AnalyzerName = Literal["claude", "openai", "manual", "heuristica"]
CATEGORY_ORDER: dict[str, int] = {"alvo": 0, "subdominio": 1, "relacionado": 2, "terceiros": 3}


class DomainMatch(BaseModel):
    domain: str
    registered_domain: str
    category: Category
    confidence: float = Field(ge=0.0, le=1.0)
    sources: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    reasoning: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def confidence_label(self) -> Literal["alta", "media", "baixa"]:
        if self.confidence >= 0.7:
            return "alta"
        if self.confidence >= 0.4:
            return "media"
        return "baixa"


class FalsePositive(BaseModel):
    domain: str
    reason: str


class LLMDomainVerdict(BaseModel):
    """Veredito do Claude para um domínio candidato."""

    domain: str
    category: Literal["relacionado", "terceiros"]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str


class LLMVerdict(BaseModel):
    """Schema exigido na resposta do Claude (validado antes de ser usado)."""

    summary: str
    matches: list[LLMDomainVerdict]
    false_positives: list[FalsePositive]


class AnalysisReport(BaseModel):
    target: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    analyzer: AnalyzerName
    model: str | None = None
    summary: str = ""
    matches: list[DomainMatch]
    false_positives: list[FalsePositive] = Field(default_factory=list)
    collector_errors: dict[str, str] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    source_counts: dict[str, int] = Field(default_factory=dict)
    elapsed_seconds: float = 0.0

    def by_category(self, category: Category) -> list[DomainMatch]:
        return [m for m in self.matches if m.category == category]
