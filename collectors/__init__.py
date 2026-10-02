from __future__ import annotations

from collections.abc import Callable, Iterable

from collectors.analytics import AnalyticsCollector
from collectors.base import Collector, CollectorError
from collectors.certspotter import CertSpotterCollector
from collectors.crtsh import CrtShCollector
from collectors.dns_tracker import DnsCollector, TldVariantsCollector
from collectors.wayback import WaybackCollector
from collectors.whois import WhoisCollector
from core.http_client import HttpClient
from core.netguard import PublicHostGuard
from core.whois43 import Whois43Client

ALL_COLLECTORS = ("crtsh", "certspotter", "dns", "tld_variants", "analytics", "whois", "wayback")
# o crt.sh vive fora do ar (502) e o CertSpotter lê os mesmos logs de Certificate
# Transparency; ele só entra por padrão com --org, a busca por organização que
# só o crt.sh oferece
DEFAULT_COLLECTORS = tuple(n for n in ALL_COLLECTORS if n != "crtsh")


def default_collectors(org: str | None = None) -> tuple[str, ...]:
    return ALL_COLLECTORS if org else DEFAULT_COLLECTORS


def build_collectors(
    http: HttpClient,
    names: Iterable[str] | None = None,
    *,
    org: str | None = None,
    tlds: Iterable[str] | None = None,
    certspotter_key: str | None = None,
    whois_port43: bool = True,
    public_only: bool = False,
) -> list[Collector]:
    """`public_only` aplica a proteção contra SSRF também ao WHOIS da porta 43 (o
    HttpClient tem a sua própria, ligada pelo parâmetro de mesmo nome)."""
    whois43 = (
        Whois43Client(guard=PublicHostGuard() if public_only else None) if whois_port43 else None
    )
    names = list(default_collectors(org) if names is None else names)
    unknown = set(names) - set(ALL_COLLECTORS)
    if unknown:
        raise ValueError(f"coletores desconhecidos: {', '.join(sorted(unknown))}")
    factories: dict[str, Callable[[], Collector]] = {
        "crtsh": lambda: CrtShCollector(http, org=org),
        "certspotter": lambda: CertSpotterCollector(http, api_key=certspotter_key),
        "dns": lambda: DnsCollector(http),
        "tld_variants": lambda: TldVariantsCollector(http, tlds=tlds),
        "analytics": lambda: AnalyticsCollector(http),
        "whois": lambda: WhoisCollector(http, whois43),
        "wayback": lambda: WaybackCollector(http),
    }
    return [factories[n]() for n in names]


__all__ = [
    "ALL_COLLECTORS",
    "DEFAULT_COLLECTORS",
    "Collector",
    "CollectorError",
    "build_collectors",
    "default_collectors",
]
