"""Certificate Transparency via crt.sh."""

from __future__ import annotations

from typing import Any

import httpx

from collectors.base import Collector
from core.domains import normalize
from core.http_client import HttpClient
from models import Collected, Finding

CRTSH_URL = "https://crt.sh/"
# o crt.sh responde 502 com frequência e se recupera em segundos; com backoff de
# 1s isso dá 1+2+4+8 = 15s de espera no pior caso, dentro do timeout do coletor
CRTSH_RETRIES = 4


def parse_crtsh(data: Any, source: str, evidence_prefix: str) -> list[Finding]:
    found: dict[str, Finding] = {}
    for entry in data or []:
        for field in ("name_value", "common_name"):
            for name in str(entry.get(field) or "").split("\n"):
                domain = normalize(name)
                if domain and domain not in found:
                    found[domain] = Finding(
                        domain=domain,
                        source=source,
                        evidence=f"{evidence_prefix} (cert id {entry.get('id')})",
                    )
    return list(found.values())


class CrtShCollector(Collector):
    """Subdomínios em certificados emitidos para *.alvo e, com `org`, domínios de
    certificados cujo campo Organization (O=) é a empresa (revela outras marcas)."""

    name = "crtsh"
    weight = 0.5
    timeout = 90.0  # crt.sh costuma ser lento

    def __init__(self, http: HttpClient, org: str | None = None) -> None:
        super().__init__(http)
        self.org = org

    @property
    def _retries(self) -> int:
        # respeita retries=0 do cliente (modo --replay e testes)
        return max(self.http.retries, CRTSH_RETRIES) if self.http.retries else 0

    async def collect(self, target: str) -> Collected:
        data = await self.http.get_json(
            CRTSH_URL, params={"q": f"%.{target}", "output": "json"}, retries=self._retries
        )
        findings = parse_crtsh(data, self.name, "certificado CT")
        metadata: dict[str, Any] = {}
        if self.org:
            # a consulta por organização é complementar: falha nela não descarta a principal
            try:
                org_data = await self.http.get_json(
                    CRTSH_URL, params={"O": self.org, "output": "json"}, retries=self._retries
                )
            except httpx.HTTPError as exc:
                metadata["org_error"] = f"{type(exc).__name__}: {exc}"
            else:
                findings += parse_crtsh(org_data, "crtsh_org", f"certificado com O={self.org}")
                metadata["org"] = self.org
        return Collected(findings=findings, metadata=metadata)
