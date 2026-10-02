"""Registros DNS via DNS-over-HTTPS (JSON).

- DnsCollector: domínios citados em MX, NS, SPF, DMARC e CNAME do alvo.
- TldVariantsCollector: mesmo nome da empresa em outros TLDs (sinal fraco).
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable
from dataclasses import dataclass

import httpx

from collectors.base import Collector, CollectorError
from core.domains import normalize, registered_domain
from core.http_client import HttpClient
from core.providers import PARKING_NS, is_third_party
from models import Collected, Finding

DOH_URL = "https://cloudflare-dns.com/dns-query"
RR_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}

SPF_MECHANISMS = ("include:", "redirect=", "a:", "mx:", "exists:", "ptr:")
_TXT_CHUNK_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

DEFAULT_TLDS = (
    "com", "com.br", "net", "net.br", "org", "org.br", "io", "co", "app",
    "dev", "info", "biz", "tech", "online", "store", "ai", "us", "eu", "co.uk", "de",
)  # fmt: skip


@dataclass(frozen=True)
class DnsAnswer:
    status: int  # 0 = NOERROR, 3 = NXDOMAIN
    records: list[str]


class DohResolver:
    def __init__(self, http: HttpClient, url: str = DOH_URL) -> None:
        self.http = http
        self.url = url

    async def query(self, name: str, rtype: str) -> DnsAnswer:
        data = await self.http.get_json(
            self.url,
            params={"name": name, "type": rtype},
            headers={"accept": "application/dns-json"},
        )
        code = RR_TYPES[rtype]
        records = [a["data"] for a in data.get("Answer", []) if a.get("type") == code]
        return DnsAnswer(int(data.get("Status", 2)), records)


def join_txt(data: str) -> str:
    """'"v=spf1 " "include:x ~all"' -> 'v=spf1 include:x ~all'"""
    chunks = _TXT_CHUNK_RE.findall(data)
    return "".join(chunks) if chunks else data


def parse_spf(txt: str) -> list[tuple[str, str]]:
    """Devolve (mecanismo, domínio) de um registro SPF."""
    if not txt.lower().startswith("v=spf1"):
        return []
    out = []
    for token in txt.split()[1:]:
        token = token.lstrip("+-~?")
        for prefix in SPF_MECHANISMS:
            if token.lower().startswith(prefix):
                value = token[len(prefix) :].split("/", 1)[0]
                if value and "%" not in value:  # ignora macros SPF
                    out.append((prefix.rstrip(":="), value))
                break
    return out


def parse_dmarc(txt: str) -> list[str]:
    """Domínios dos destinatários de relatório (rua/ruf) de um DMARC."""
    if not txt.lower().startswith("v=dmarc1"):
        return []
    domains = []
    for tag in txt.split(";"):
        key, _, value = tag.strip().partition("=")
        if key.strip().lower() in ("rua", "ruf"):
            for uri in value.split(","):
                uri = uri.strip().split("!", 1)[0]
                if "@" in uri:
                    domains.append(uri.rsplit("@", 1)[1])
    return domains


class DnsCollector(Collector):
    name = "dns"
    weight = 0.6

    def __init__(self, http: HttpClient, resolver: DohResolver | None = None) -> None:
        super().__init__(http)
        self.resolver = resolver or DohResolver(http)

    async def collect(self, target: str) -> Collected:
        root = registered_domain(target)
        queries = [
            (root, "MX"),
            (root, "NS"),
            (root, "TXT"),
            (f"_dmarc.{root}", "TXT"),
            (f"www.{root}", "CNAME"),
        ]
        answers = await asyncio.gather(
            *(self.resolver.query(n, t) for n, t in queries), return_exceptions=True
        )

        findings: list[Finding] = []
        errors: list[str] = []

        def add(names: Iterable[tuple[str, str]]) -> None:
            for name, evidence in names:
                domain = normalize(name)
                if domain and domain != root:
                    findings.append(Finding(domain=domain, source=self.name, evidence=evidence))

        for (qname, rtype), ans in zip(queries, answers, strict=True):
            if isinstance(ans, BaseException):
                if not isinstance(ans, httpx.HTTPError | ValueError | KeyError | AttributeError):
                    raise ans
                errors.append(f"{rtype} {qname}: {ans}")
                continue
            if rtype == "MX":
                add((mx.split()[-1], "registro MX") for mx in ans.records)
            elif rtype == "NS":
                add((ns, "registro NS") for ns in ans.records)
            elif rtype == "CNAME":
                add((cname, f"CNAME de {qname}") for cname in ans.records)
            elif qname.startswith("_dmarc."):
                add(
                    (d, "DMARC (destino de relatórios)")
                    for txt in ans.records
                    for d in parse_dmarc(join_txt(txt))
                )
            else:
                add(
                    (value, f"SPF {mech}")
                    for txt in ans.records
                    for mech, value in parse_spf(join_txt(txt))
                )

        if len(errors) == len(queries):
            raise CollectorError("todas as consultas DNS falharam: " + "; ".join(errors))
        return Collected(findings=findings, metadata={"errors": errors} if errors else {})


SHARED_NS_SOURCE = "tld_variants_ns"
PARKED_SOURCE = "tld_variants_parked"


def ns_owners(records: Iterable[str]) -> set[str]:
    """Domínios registrados dos nameservers, sem provedores públicos de DNS
    (dividir Cloudflare com o alvo não indica dono em comum)."""
    owners = set()
    for record in records:
        name = normalize(record)
        if name and not is_third_party(name):
            owners.add(registered_domain(name))
    return owners


class TldVariantsCollector(Collector):
    """Mesmo nome da empresa registrado em outros TLDs (empresa.com, empresa.net...).

    Sinal fraco: o domínio pode pertencer a outra organização; o Claude decide.
    Exceção: se a variação usa os mesmos nameservers próprios do alvo, o achado
    vira a fonte `tld_variants_ns`, de peso maior."""

    name = "tld_variants"
    weight = 0.2

    def __init__(
        self,
        http: HttpClient,
        tlds: Iterable[str] | None = None,
        resolver: DohResolver | None = None,
        concurrency: int = 8,
    ) -> None:
        super().__init__(http)
        self.tlds = tuple(tlds or DEFAULT_TLDS)
        self.resolver = resolver or DohResolver(http)
        self._sem = asyncio.Semaphore(concurrency)

    def candidates(self, target: str) -> list[str]:
        root = registered_domain(target)
        label = root.split(".")[0]
        return sorted({f"{label}.{tld.strip('.')}" for tld in self.tlds} - {root})

    async def _target_ns_owners(self, target: str) -> set[str]:
        try:
            answer = await self.resolver.query(registered_domain(target), "NS")
        except (httpx.HTTPError, ValueError, KeyError, AttributeError):
            return set()
        return ns_owners(answer.records)

    async def _check(self, domain: str, target_owners: set[str]) -> Finding | bool | None:
        """Finding se existe, None se não existe, False se a consulta falhou."""
        async with self._sem:
            try:
                answer = await self.resolver.query(domain, "NS")
            except (httpx.HTTPError, ValueError, KeyError, AttributeError):
                return False
        if answer.status == 0 and answer.records:
            ns = ", ".join(r.rstrip(".") for r in answer.records[:2])
            owners = {registered_domain(n) for n in map(normalize, answer.records) if n}
            parked = sorted(owners & PARKING_NS)
            if parked:
                return Finding(
                    domain=domain,
                    source=PARKED_SOURCE,
                    evidence=f"mesmo nome em outro TLD, estacionado ({parked[0]})",
                )
            shared = sorted(ns_owners(answer.records) & target_owners)
            if shared:
                return Finding(
                    domain=domain,
                    source=SHARED_NS_SOURCE,
                    evidence=f"mesmo nome em outro TLD, com os nameservers do alvo ({shared[0]})",
                )
            return Finding(
                domain=domain, source=self.name, evidence=f"mesmo nome em outro TLD (NS: {ns})"
            )
        return None

    async def collect(self, target: str) -> Collected:
        cands = self.candidates(target)
        target_owners = await self._target_ns_owners(target)
        results = await asyncio.gather(*(self._check(d, target_owners) for d in cands))
        if cands and all(r is False for r in results):
            raise CollectorError("nenhuma variação de TLD pôde ser verificada")
        return Collected(findings=[r for r in results if isinstance(r, Finding)])
