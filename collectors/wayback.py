"""Hostnames históricos do Internet Archive (CDX API)."""

from __future__ import annotations

from urllib.parse import urlsplit

from collectors.base import Collector
from core.domains import normalize
from core.http_client import HttpClient
from models import Collected, Finding

WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"


class WaybackCollector(Collector):
    name = "wayback"
    weight = 0.3
    timeout = 90.0  # a CDX API levou ~40s em testes reais

    def __init__(self, http: HttpClient, limit: int = 10000) -> None:
        super().__init__(http)
        self.limit = limit

    async def collect(self, target: str) -> Collected:
        rows = await self.http.get_json(
            WAYBACK_CDX_URL,
            params={
                "url": f"*.{target}",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": self.limit,
            },
        )
        found: dict[str, Finding] = {}
        metadata: dict[str, str] = {}
        if rows and len(rows) - 1 >= self.limit:
            metadata["truncated"] = (
                f"limite de {self.limit} URLs atingido; pode haver mais hostnames históricos"
            )
        for row in (rows or [])[1:]:  # a primeira linha é o cabeçalho
            if not row:
                continue
            original = str(row[0])
            try:
                host = urlsplit(original if "://" in original else f"http://{original}").hostname
            except ValueError:
                continue
            domain = normalize(host)
            if domain:
                found.setdefault(
                    domain, Finding(domain=domain, source=self.name, evidence="URL arquivada")
                )
        return Collected(findings=list(found.values()), metadata=metadata)
