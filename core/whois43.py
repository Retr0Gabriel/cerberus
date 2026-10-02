"""WHOIS clássico (TCP, porta 43), usado quando o TLD não publica RDAP (ex.: .me).

Fluxo: pergunta ao whois.iana.org qual servidor responde pelo TLD (linha
`refer:`), consulta esse servidor e, se ele indicar o servidor do registrar
(registros "thin"), segue a indicação uma vez.

Assíncrono (asyncio streams), com timeout explícito e limite de tamanho. Não é
HTTP, então não passa pelo HttpClient nem aparece no HAR do --har. Muitas redes
corporativas e alguns ambientes de nuvem bloqueiam a porta 43.

Por privacidade, o parser guarda só organização, registrar, nameservers, datas e
o *domínio* dos e-mails, como o coletor RDAP; nomes de pessoas são ignorados.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from core.domains import normalize
from core.netguard import BlockedDestinationError, PublicHostGuard

IANA_WHOIS = "whois.iana.org"
PORT = 43
MAX_BYTES = 1_000_000

_REDACTED_RE = re.compile(r"redacted|privacy|private|protected|withheld|not disclosed|gdpr", re.I)
_LINE_RE = re.compile(r"^\s*([^:%#>]{2,60}?)\s*:\s*(.+?)\s*$")
_EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")

_EVENT_KEYS = {
    "creation date": "registration",
    "created": "registration",
    "registered on": "registration",
    "registry expiry date": "expiration",
    "registrar registration expiration date": "expiration",
    "expiry date": "expiration",
    "expires": "expiration",
    "updated date": "last changed",
    "last updated": "last changed",
    "changed": "last changed",
}
_ORG_KEYS = {"registrant organization", "registrant organisation", "org", "organisation"}
_NS_KEYS = {"name server", "nameserver", "nserver"}
_REFERRAL_KEYS = {"registrar whois server", "whois server", "refer", "whois"}


class WhoisError(RuntimeError):
    pass


class Whois43Client:
    """Cliente mínimo do protocolo WHOIS (RFC 3912)."""

    def __init__(
        self, timeout: float = 15.0, port: int = PORT, guard: PublicHostGuard | None = None
    ) -> None:
        self.timeout = timeout
        self.port = port
        # o servidor "indicado" vem da resposta de outro servidor: só endereços públicos
        self.guard = guard

    async def query(self, server: str, text: str) -> str:
        if self.guard is not None:
            try:
                await self.guard.ensure_public(server)
            except BlockedDestinationError as exc:
                raise WhoisError(str(exc)) from exc
        try:
            return await asyncio.wait_for(self._query(server, text), self.timeout)
        except TimeoutError as exc:
            raise WhoisError(
                f"WHOIS {server}:{self.port} sem resposta em {self.timeout:.0f}s"
            ) from exc
        except OSError as exc:  # recusado, DNS, rede sem acesso à porta 43...
            raise WhoisError(f"WHOIS {server}:{self.port} inacessível: {exc}") from exc

    async def _query(self, server: str, text: str) -> str:
        reader, writer = await asyncio.open_connection(server, self.port)
        try:
            writer.write(f"{text}\r\n".encode("idna" if not text.isascii() else "ascii"))
            await writer.drain()
            data = await reader.read(MAX_BYTES)
            chunks = [data]
            while data and sum(map(len, chunks)) < MAX_BYTES:
                data = await reader.read(MAX_BYTES)
                chunks.append(data)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        return b"".join(chunks).decode("utf-8", errors="replace")


def _fields(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        m = _LINE_RE.match(line)
        if m:
            out.append((m.group(1).strip().lower(), m.group(2).strip()))
    return out


def referral(text: str, current: str) -> str | None:
    """Servidor indicado na resposta (IANA `refer:` ou `Registrar WHOIS Server:`)."""
    for key, value in _fields(text):
        if key in _REFERRAL_KEYS:
            server = normalize(value)
            if server and server != current:
                return server
    return None


def parse_whois(text: str) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """Mesmo formato do parse_rdap: (metadados, [(domínio, evidência)])."""
    meta: dict[str, Any] = {}
    related: list[tuple[str, str]] = []
    orgs: set[str] = set()
    email_domains: set[str] = set()
    nameservers: list[str] = []
    events: dict[str, str] = {}

    for key, value in _fields(text):
        if key == "registrar" and "registrar" not in meta and not _REDACTED_RE.search(value):
            meta["registrar"] = value
        elif key in _ORG_KEYS and not _REDACTED_RE.search(value):
            orgs.add(value)
        elif key in _NS_KEYS:
            ns = normalize(value.split()[0])
            if ns and ns not in nameservers:
                nameservers.append(ns)
                related.append((ns, "nameserver no WHOIS"))
        elif key in _EVENT_KEYS and _EVENT_KEYS[key] not in events:
            events[_EVENT_KEYS[key]] = value
        for domain in _EMAIL_RE.findall(value):
            d = normalize(domain)
            if d and d not in email_domains and not _REDACTED_RE.search(value):
                email_domains.add(d)
                related.append((d, f"e-mail de contato WHOIS ({key})"))

    if orgs:
        meta["organizations"] = sorted(orgs)
    if email_domains:
        meta["contact_email_domains"] = sorted(email_domains)
    if nameservers:
        meta["nameservers"] = nameservers
    if events:
        meta["events"] = events
    return meta, related


async def lookup(client: Whois43Client, domain: str) -> tuple[str, str]:
    """(servidor que respondeu, texto da resposta) para o domínio."""
    tld = domain.rsplit(".", 1)[-1]
    iana = await client.query(IANA_WHOIS, tld)
    server = referral(iana, IANA_WHOIS)
    if not server:
        raise WhoisError(f"a IANA não indica servidor WHOIS para .{tld}")
    text = await client.query(server, domain)
    registrar_server = referral(text, server)
    if registrar_server:
        # registro "thin": os detalhes ficam no servidor do registrar; se ele falhar
        # ou responder sem dados úteis, fica valendo a resposta do registro
        try:
            detail = await client.query(registrar_server, domain)
        except WhoisError:
            detail = ""
        if any(parse_whois(detail)):
            return registrar_server, detail
    return server, text
