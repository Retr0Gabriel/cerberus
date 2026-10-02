"""Dados brutos produzidos pelos coletores."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Finding(BaseModel):
    """Um domínio encontrado por um coletor, com a evidência que o justifica."""

    model_config = ConfigDict(frozen=True)

    domain: str
    source: str
    evidence: str = ""


class Collected(BaseModel):
    """Retorno de `Collector.collect`: domínios + contexto extra (WHOIS, trackers...)."""

    findings: list[Finding] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CollectorResult(BaseModel):
    name: str
    findings: list[Finding] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    elapsed_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.error is None


class RawData(BaseModel):
    """Tudo o que foi coletado para um alvo, antes da correlação."""

    target: str
    results: list[CollectorResult]

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    @property
    def errors(self) -> dict[str, str]:
        return {r.name: r.error for r in self.results if r.error is not None}

    @property
    def source_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.source] = counts.get(f.source, 0) + 1
        return counts

    @property
    def context(self) -> dict[str, dict[str, Any]]:
        """Metadados não vazios por coletor (enviados ao Claude como contexto)."""
        return {r.name: r.metadata for r in self.results if r.metadata}
