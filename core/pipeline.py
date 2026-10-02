"""Orquestra: coleta assíncrona -> pré-classificação heurística -> correlação com o Claude."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable, Sequence

from collectors import Collector
from core.domains import is_subdomain_of, normalize, registered_domain
from core.llm import Analyzer, Guardrails, LLMAnalysisError
from core.providers import is_third_party
from models import (
    CATEGORY_ORDER,
    AnalysisReport,
    Category,
    CollectorResult,
    DomainMatch,
    FalsePositive,
    LLMVerdict,
    RawData,
)

MAX_EVIDENCE = 8
# quantos candidatos vão à revisão por IA: com milhares, um modelo local levaria horas
MAX_REVIEW = 300
DEFAULT_WEIGHT = 0.3
# fontes emitidas por um coletor com nome diferente do seu
EXTRA_SOURCE_WEIGHTS = {
    "crtsh_org": 0.6,  # certificado com O=organização do alvo
    "analytics_link": 0.15,  # link qualquer na home: sinal fraco
    "tld_variants_ns": 0.6,  # outro TLD com os mesmos nameservers do alvo
    "tld_variants_parked": 0.05,  # outro TLD estacionado/à venda: quase certamente outro dono
}


def normalize_target(target: str) -> str:
    clean = normalize(target)
    if not clean:
        raise ValueError(f"domínio inválido: {target!r}")
    return registered_domain(clean)


async def collect_all(collectors: Sequence[Collector], target: str) -> RawData:
    """Roda todos os coletores em paralelo; falha de um não afeta os demais."""
    if not collectors:
        raise ValueError("nenhum coletor configurado")
    outcomes = await asyncio.gather(*(c.run(target) for c in collectors), return_exceptions=True)
    results: list[CollectorResult] = []
    for col, out in zip(collectors, outcomes, strict=True):
        if isinstance(out, CollectorResult):
            results.append(out)
        elif isinstance(out, Exception):  # erro inesperado que escapou do run()
            results.append(CollectorResult(name=col.name, error=f"{type(out).__name__}: {out}"))
        else:
            raise out  # KeyboardInterrupt/CancelledError
    return RawData(target=target, results=results)


def classify(domain: str, root: str, extra_third_party: frozenset[str]) -> Category:
    if domain == root:
        return "alvo"
    if is_subdomain_of(domain, root):
        return "subdominio"
    if is_third_party(domain, extra_third_party):
        return "terceiros"
    return "relacionado"


def build_candidates(
    raw: RawData,
    weights: dict[str, float],
    extra_third_party: frozenset[str] = frozenset(),
) -> list[DomainMatch]:
    """Deduplica os achados e calcula uma confiança heurística por domínio."""
    merged: dict[str, DomainMatch] = {}
    for f in raw.findings:
        domain = normalize(f.domain)
        if not domain:
            continue
        match = merged.get(domain)
        if match is None:
            match = merged[domain] = DomainMatch(
                domain=domain,
                registered_domain=registered_domain(domain),
                category=classify(domain, raw.target, extra_third_party),
                confidence=0.0,
            )
        if f.source not in match.sources:
            match.sources.append(f.source)
        ev = f"{f.source}: {f.evidence}" if f.evidence else f.source
        if ev not in match.evidence and len(match.evidence) < MAX_EVIDENCE:
            match.evidence.append(ev)

    for match in merged.values():
        # probabilidade combinada: 1 - prod(1 - peso)
        miss = 1.0
        for s in match.sources:
            miss *= 1.0 - weights.get(s, DEFAULT_WEIGHT)
        match.confidence = round(1.0 - miss, 2)
        match.sources.sort()
        if match.category in ("alvo", "subdominio"):  # pertence ao alvo por definição de DNS
            match.confidence = max(match.confidence, 0.7)
    return sort_matches(merged.values())


def sort_matches(matches: Iterable[DomainMatch]) -> list[DomainMatch]:
    return sorted(
        matches,
        key=lambda m: (
            CATEGORY_ORDER[m.category],
            -m.confidence,
            m.registered_domain,
            m.domain.count("."),
            m.domain,
        ),
    )


def needs_review(match: DomainMatch) -> bool:
    return match.category in ("relacionado", "terceiros")


def apply_verdict(
    candidates: list[DomainMatch],
    verdict: LLMVerdict,
    guardrails: Guardrails | None = None,
) -> tuple[list[DomainMatch], list[FalsePositive]]:
    """Aplica o veredito do modelo. Domínios que o modelo não conhece (não estavam
    entre os candidatos) são ignorados; candidatos que ele não avaliou são mantidos
    com a classificação heurística. Com `guardrails`, evidência forte não pode ser
    descartada e a confiança só se move dentro do limite."""
    by_domain = {c.domain: c for c in candidates}
    rejected: dict[str, FalsePositive] = {}
    overruled: dict[str, str] = {}
    for fp in verdict.false_positives:
        cand = by_domain.get(fp.domain)
        if cand is None or not needs_review(cand):
            continue
        if guardrails and cand.confidence >= guardrails.protect_from:
            overruled[fp.domain] = (
                f"modelo sugeriu descartar ({fp.reason}); mantido por evidência forte"
            )
        else:
            rejected[fp.domain] = fp

    reviewed: dict[str, DomainMatch] = {}
    for v in verdict.matches:
        cand = by_domain.get(v.domain)
        if cand is None or not needs_review(cand) or v.domain in rejected:
            continue
        confidence = v.confidence
        if guardrails:
            low, high = (
                cand.confidence - guardrails.max_shift,
                cand.confidence + guardrails.max_shift,
            )
            confidence = round(min(max(confidence, low, 0.0), high, 1.0), 2)
        reviewed[v.domain] = cand.model_copy(
            update={"category": v.category, "confidence": confidence, "reasoning": v.reasoning}
        )

    kept: list[DomainMatch] = []
    for cand in candidates:
        if cand.domain in rejected:
            continue
        if cand.domain in reviewed:
            kept.append(reviewed[cand.domain])
        elif cand.domain in overruled:
            kept.append(cand.model_copy(update={"reasoning": overruled[cand.domain]}))
        elif needs_review(cand):
            kept.append(cand.model_copy(update={"reasoning": "não avaliado pelo modelo"}))
        else:
            kept.append(cand)
    return sort_matches(kept), list(rejected.values())


async def collect_and_classify(
    target: str,
    collectors: Sequence[Collector],
    extra_third_party: frozenset[str] = frozenset(),
) -> tuple[RawData, AnalysisReport]:
    """Coleta + heurística. Devolve também os dados brutos, usados para montar o
    pedido ao modelo (inclusive no modo manual, em que a revisão vem depois)."""
    root = normalize_target(target)
    start = time.monotonic()
    raw = await collect_all(collectors, root)
    weights = EXTRA_SOURCE_WEIGHTS | {c.name: c.weight for c in collectors}
    report = AnalysisReport(
        target=root,
        analyzer="heuristica",
        matches=build_candidates(raw, weights, extra_third_party),
        collector_errors=raw.errors,
        source_counts=raw.source_counts,
        elapsed_seconds=round(time.monotonic() - start, 2),
        # limites atingidos pelos coletores não podem passar em silêncio
        warnings=[
            f"{r.name}: {r.metadata['truncated']}" for r in raw.results if "truncated" in r.metadata
        ],
    )
    return raw, report


def select_for_review(report: AnalysisReport, max_review: int = MAX_REVIEW) -> list[DomainMatch]:
    """Candidatos que vão ao modelo (os mais fortes primeiro, já ordenados) e, se o
    limite cortar algum, um aviso no relatório."""
    to_review = [c for c in report.matches if needs_review(c)]
    if len(to_review) > max_review:
        report.warnings.append(
            f"{len(to_review) - max_review} candidatos não foram revisados pela IA "
            f"(limite de {max_review}; ajuste com --max-review) e ficam com a "
            "classificação heurística"
        )
    return to_review[:max_review]


def apply_review(
    report: AnalysisReport,
    verdict: LLMVerdict,
    analyzer: str,
    model: str | None,
    guardrails: Guardrails | None = None,
) -> AnalysisReport:
    """Aplica um veredito (de qualquer analisador) a um relatório heurístico."""
    matches, false_positives = apply_verdict(report.matches, verdict, guardrails)
    return report.model_copy(
        update={
            "matches": matches,
            "false_positives": false_positives,
            "analyzer": analyzer,
            "model": model,
            "summary": verdict.summary,
        }
    )


async def analyze(
    target: str,
    collectors: Sequence[Collector],
    analyzer: Analyzer | None = None,
    extra_third_party: frozenset[str] = frozenset(),
    max_review: int = MAX_REVIEW,
) -> AnalysisReport:
    """Pipeline completo. Sem `analyzer` (ou se o modelo falhar), devolve a
    classificação heurística; a falha fica registrada em `warnings`."""
    start = time.monotonic()
    raw, report = await collect_and_classify(target, collectors, extra_third_party)

    to_review = select_for_review(report, max_review) if analyzer is not None else []
    if analyzer is not None and to_review:
        try:
            verdict = await analyzer.review(raw, to_review)
        except LLMAnalysisError as exc:
            report.warnings.append(f"{exc} — exibindo apenas a classificação heurística")
        else:
            report = apply_review(
                report, verdict, analyzer.name, analyzer.model, analyzer.guardrails
            )

    report.elapsed_seconds = round(time.monotonic() - start, 2)
    return report
