"""Página inicial do alvo: IDs de trackers/analytics, redirecionamentos e links.

IDs compartilhados (mesmo Google Analytics, GTM, Pixel ou AdSense) são um dos
sinais mais fortes de que dois sites pertencem à mesma organização. Aqui eles
são extraídos como contexto para o Claude; a busca reversa por ID exige
serviços pagos e fica para uma próxima etapa.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from collectors.base import Collector
from core.domains import normalize, registered_domain
from models import Collected, Finding

MAX_HTML_CHARS = 2_000_000

TRACKER_PATTERNS: dict[str, re.Pattern[str]] = {
    "google_analytics_ua": re.compile(r"\b(UA-\d{4,10}-\d{1,4})\b"),
    # entre aspas (gtag('config', 'G-...')) ou no loader (gtag/js?id=G-...)
    "google_analytics_ga4": re.compile(r"""(?:['"]|[?&]id=)(G-[A-Z0-9]{6,12})\b"""),
    "google_tag_manager": re.compile(r"\b(GTM-[A-Z0-9]{4,9})\b"),
    "google_adsense": re.compile(r"\b(ca-pub-\d{10,20})\b"),
    "facebook_pixel": re.compile(r"""fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,20})['"]"""),
    "hotjar": re.compile(r"\bhjid\s*[:=]\s*(\d{5,10})\b"),
}

_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*['"](https?://[^'"\s>]+)""", re.IGNORECASE)


def extract_trackers(html: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for name, pattern in TRACKER_PATTERNS.items():
        ids = sorted(set(pattern.findall(html)))
        if ids:
            found[name] = ids
    return found


def extract_link_domains(html: str) -> list[str]:
    domains = {normalize(url) for url in _LINK_RE.findall(html)}
    return sorted(d for d in domains if d)


# links da página são sinal fraco (redes sociais, parceiros, notícias...); o
# redirecionamento da home para outro domínio é sinal forte e usa `name`
LINK_SOURCE = "analytics_link"


class AnalyticsCollector(Collector):
    name = "analytics"
    weight = 0.7
    timeout = 45.0

    async def _fetch_homepage(self, target: str) -> httpx.Response:
        last: httpx.HTTPError | None = None
        for url in (f"https://{target}/", f"https://www.{target}/"):
            try:
                return await self.http.get(url)
            except httpx.HTTPError as exc:
                last = exc
        assert last is not None
        raise last

    async def collect(self, target: str) -> Collected:
        resp = await self._fetch_homepage(target)
        html = resp.text[:MAX_HTML_CHARS]
        root = registered_domain(target)
        findings: list[Finding] = []

        final_host = normalize(resp.url.host)
        if final_host and registered_domain(final_host) != root:
            findings.append(
                Finding(
                    domain=final_host,
                    source=self.name,
                    evidence=f"página inicial de {target} redireciona para {final_host}",
                )
            )
        for domain in extract_link_domains(html):
            if registered_domain(domain) != root and domain != final_host:
                findings.append(
                    Finding(domain=domain, source=LINK_SOURCE, evidence="link na página inicial")
                )

        metadata: dict[str, Any] = {"final_url": str(resp.url)}
        trackers = extract_trackers(html)
        if trackers:
            metadata["trackers"] = trackers
        return Collected(findings=findings, metadata=metadata)
