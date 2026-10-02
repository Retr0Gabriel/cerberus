"""Certificate Transparency via API CertSpotter (SSLMate).

Com expand=dns_names retorna todos os SANs do certificado, o que também revela
domínios de outras marcas que compartilham o mesmo certificado."""

from __future__ import annotations

from collectors.base import Collector
from core.domains import normalize
from core.http_client import HttpClient
from models import Collected, Finding

CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"


class CertSpotterCollector(Collector):
    name = "certspotter"
    weight = 0.5

    def __init__(self, http: HttpClient, api_key: str | None = None, max_pages: int = 5) -> None:
        super().__init__(http)
        self.api_key = api_key
        self.max_pages = max_pages

    async def collect(self, target: str) -> Collected:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else None
        found: dict[str, Finding] = {}
        after: str | None = None
        metadata: dict[str, str] = {}
        for page_number in range(1, self.max_pages + 1):
            params = {"domain": target, "include_subdomains": "true", "expand": "dns_names"}
            if after:
                params["after"] = after
            page = await self.http.get_json(CERTSPOTTER_URL, params=params, headers=headers)
            if not page:
                break
            for issuance in page:
                names = [d for d in (normalize(n) for n in issuance.get("dns_names", [])) if d]
                note = f" (SAN compartilhado com {len(names)} nomes)" if len(names) > 1 else ""
                for domain in names:
                    found.setdefault(
                        domain,
                        Finding(
                            domain=domain,
                            source=self.name,
                            evidence=f"certificado {issuance.get('id')}{note}",
                        ),
                    )
            after = page[-1].get("id")
            if not after:
                break
            if page_number == self.max_pages:
                metadata["truncated"] = (
                    f"parou no limite de {self.max_pages} páginas; pode haver mais certificados"
                )
        return Collected(findings=list(found.values()), metadata=metadata)
