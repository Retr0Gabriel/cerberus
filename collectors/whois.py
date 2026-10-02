"""Dados de registro via RDAP (sucessor do WHOIS, em JSON sobre HTTPS).

Por privacidade, e-mails de contato são reduzidos ao domínio; nomes de pessoas
não são coletados, apenas organização e registrar."""

from __future__ import annotations

from typing import Any

import httpx

from collectors.base import Collector, CollectorError
from core.domains import normalize, registered_domain
from core.http_client import HttpClient
from core.whois43 import Whois43Client, WhoisError, lookup, parse_whois
from models import Collected, Finding

RDAP_URL = "https://rdap.org/domain/{domain}"
# lista oficial de TLDs com servidor RDAP; nem todos têm (ex.: .me)
IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"


def _vcard_fields(entity: dict[str, Any]) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    vcard = entity.get("vcardArray") or []
    if len(vcard) == 2 and isinstance(vcard[1], list):
        for prop in vcard[1]:
            if isinstance(prop, list) and len(prop) >= 4 and isinstance(prop[3], str):
                fields.setdefault(str(prop[0]).lower(), []).append(prop[3])
    return fields


def _walk_entities(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ent in entities or []:
        out.append(ent)
        out.extend(_walk_entities(ent.get("entities") or []))
    return out


def parse_rdap(data: dict[str, Any]) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """Devolve (metadados, [(domínio, evidência)])."""
    meta: dict[str, Any] = {}
    related: list[tuple[str, str]] = []
    orgs: set[str] = set()
    email_domains: set[str] = set()

    for ent in _walk_entities(data.get("entities") or []):
        roles = [str(r) for r in ent.get("roles") or []]
        vc = _vcard_fields(ent)
        if "registrar" in roles:
            meta["registrar"] = (vc.get("fn") or [ent.get("handle", "")])[0]
            continue
        orgs.update(vc.get("org", []))
        if "registrant" in roles and "org" in vc.get("kind", []):
            orgs.update(vc.get("fn", []))  # vCard kind=org: fn é a razão social
        for email in vc.get("email", []):
            domain = normalize(email)
            if domain:
                email_domains.add(domain)
                related.append((domain, f"e-mail de contato RDAP ({'/'.join(roles) or 'n/d'})"))

    nameservers = []
    for ns in data.get("nameservers") or []:
        name = normalize(ns.get("ldhName"))
        if name:
            nameservers.append(name)
            related.append((name, "nameserver no RDAP"))

    events = {
        str(e.get("eventAction")): str(e.get("eventDate"))
        for e in data.get("events") or []
        if e.get("eventAction") in ("registration", "expiration", "last changed")
    }
    if orgs:
        meta["organizations"] = sorted(orgs)
    if email_domains:
        meta["contact_email_domains"] = sorted(email_domains)
    if nameservers:
        meta["nameservers"] = nameservers
    if events:
        meta["events"] = events
    return meta, related


class WhoisCollector(Collector):
    """RDAP primeiro; se o TLD não publica RDAP, WHOIS clássico na porta 43.

    `whois43=None` desliga o fallback (modo --replay, que não pode tocar a rede)."""

    name = "whois"
    weight = 0.5

    def __init__(self, http: HttpClient, whois43: Whois43Client | None = None) -> None:
        super().__init__(http)
        self.whois43 = whois43

    async def _port43(self, root: str, tld: str) -> Collected:
        assert self.whois43 is not None
        try:
            server, text = await lookup(self.whois43, root)
        except WhoisError as exc:
            raise CollectorError(
                f"o TLD .{tld} não publica dados RDAP e o WHOIS na porta 43 falhou: {exc}"
            ) from exc
        meta, related = parse_whois(text)
        if not meta and not related:
            raise CollectorError(f"WHOIS ({server}) sem dados reconhecíveis para {root}")
        meta = {"protocol": "whois (porta 43)", "whois_server": server, **meta}
        findings = [
            Finding(domain=d, source=self.name, evidence=ev) for d, ev in related if d != root
        ]
        return Collected(findings=findings, metadata=meta)

    async def _tld_has_rdap(self, tld: str) -> bool | None:
        """True/False segundo a IANA; None se a lista não pôde ser consultada."""
        try:
            data = await self.http.get_json(IANA_RDAP_BOOTSTRAP)
            return any(tld in tlds for tlds, _urls in data["services"])
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return None

    async def collect(self, target: str) -> Collected:
        root = registered_domain(target)
        try:
            data = await self.http.get_json(RDAP_URL.format(domain=root))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
            # o rdap.org responde 404 tanto para "TLD sem RDAP" quanto para
            # "domínio não encontrado"; a IANA desfaz a ambiguidade
            tld = root.rsplit(".", 1)[-1]
            if await self._tld_has_rdap(tld) is False:
                if self.whois43 is not None:
                    return await self._port43(root, tld)
                raise CollectorError(
                    f"o TLD .{tld} não publica dados RDAP (WHOIS indisponível por RDAP)"
                ) from exc
            raise CollectorError(f"RDAP sem registro para {root}") from exc
        meta, related = parse_rdap(data or {})
        findings = [
            Finding(domain=d, source=self.name, evidence=ev) for d, ev in related if d != root
        ]
        return Collected(findings=findings, metadata=meta)
