from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any, ClassVar

import httpx
import pytest
import respx

from collectors import build_collectors
from collectors.analytics import AnalyticsCollector, extract_trackers
from collectors.base import Collector
from collectors.certspotter import CertSpotterCollector
from collectors.crtsh import CrtShCollector
from collectors.dns_tracker import (
    DnsCollector,
    TldVariantsCollector,
    join_txt,
    parse_dmarc,
    parse_spf,
)
from collectors.wayback import WaybackCollector
from collectors.whois import WhoisCollector, parse_rdap
from core.http_client import HttpClient
from models import Collected


def domains(result: Any) -> set[str]:
    return {f.domain for f in result.findings}


def doh_handler(
    answers: dict[tuple[str, str], dict[str, Any]],
) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        key = (request.url.params["name"], request.url.params["type"])
        return httpx.Response(200, json=answers.get(key, {"Status": 3}))

    return handler


# --- crt.sh ------------------------------------------------------------------


async def test_crtsh_extracts_and_normalizes(respx_router: respx.MockRouter, http: HttpClient):
    respx_router.get(host="crt.sh", path="/", params={"q": "%.acme.com"}).respond(
        json=[
            {"id": 1, "common_name": "*.API.acme.com", "name_value": "www.acme.com\nti@acme.com"},
            {"id": 2, "common_name": None, "name_value": "invalido..acme.com"},
        ]
    )
    result = await CrtShCollector(http).run("acme.com")
    assert result.ok
    assert domains(result) == {"api.acme.com", "www.acme.com", "acme.com"}


async def test_crtsh_org_failure_keeps_main_results(
    respx_router: respx.MockRouter, http: HttpClient
):
    respx_router.get(host="crt.sh", path="/", params={"q": "%.acme.com"}).respond(
        json=[{"id": 1, "name_value": "www.acme.com"}]
    )
    respx_router.get(host="crt.sh", path="/", params={"O": "Acme"}).respond(502)
    result = await CrtShCollector(http, org="Acme").run("acme.com")
    assert result.ok
    assert domains(result) == {"www.acme.com"}
    assert "org_error" in result.metadata


async def test_crtsh_org_findings_use_own_source(respx_router: respx.MockRouter, http: HttpClient):
    respx_router.get(host="crt.sh", path="/", params={"q": "%.acme.com"}).respond(json=[])
    respx_router.get(host="crt.sh", path="/", params={"O": "Acme"}).respond(
        json=[{"id": 9, "name_value": "acmepay.com"}]
    )
    result = await CrtShCollector(http, org="Acme").run("acme.com")
    assert [(f.domain, f.source) for f in result.findings] == [("acmepay.com", "crtsh_org")]


async def test_http_error_fails_gracefully(respx_router: respx.MockRouter, http: HttpClient):
    respx_router.get(host="crt.sh").respond(503)
    result = await CrtShCollector(http).run("acme.com")
    assert not result.ok
    assert "503" in (result.error or "")
    assert result.findings == []


async def test_network_timeout_fails_gracefully(respx_router: respx.MockRouter, http: HttpClient):
    respx_router.get(host="crt.sh").mock(side_effect=httpx.ConnectTimeout("lento"))
    result = await CrtShCollector(http).run("acme.com")
    assert result.error is not None and "ConnectTimeout" in result.error


async def test_invalid_json_fails_gracefully(respx_router: respx.MockRouter, http: HttpClient):
    respx_router.get(host="crt.sh").respond(text="<html>erro</html>")
    result = await CrtShCollector(http).run("acme.com")
    assert not result.ok


async def test_collector_total_timeout(http: HttpClient):
    class Slow(Collector):
        name = "slow"
        timeout: ClassVar[float] = 0.01

        async def collect(self, target: str) -> Collected:
            await asyncio.sleep(1)
            return Collected()

    result = await Slow(http).run("acme.com")
    assert result.error is not None and "timeout" in result.error


async def test_http_client_retries_on_5xx(respx_router: respx.MockRouter):
    route = respx_router.get("https://x.test/").mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json={"ok": True})]
    )
    async with HttpClient(retries=1, backoff=0.0) as client:
        assert await client.get_json("https://x.test/") == {"ok": True}
    assert route.call_count == 2


# --- CertSpotter / Wayback ----------------------------------------------------


async def test_certspotter_paginates(respx_router: respx.MockRouter, http: HttpClient):
    route = respx_router.get(host="api.certspotter.com").mock(
        side_effect=[
            httpx.Response(200, json=[{"id": "7", "dns_names": ["acme.com", "outramarca.com"]}]),
            httpx.Response(200, json=[]),
        ]
    )
    result = await CertSpotterCollector(http, api_key="token-de-teste").run("acme.com")
    assert domains(result) == {"acme.com", "outramarca.com"}
    assert "SAN compartilhado" in result.findings[0].evidence
    assert route.calls[1].request.url.params["after"] == "7"
    assert route.calls[0].request.headers["Authorization"] == "Bearer token-de-teste"


async def test_wayback_skips_header_and_ports(respx_router: respx.MockRouter, http: HttpClient):
    respx_router.get(host="web.archive.org").respond(
        json=[["original"], ["http://www.acme.com/"], ["dev.acme.com:8080/x"], []]
    )
    result = await WaybackCollector(http).run("acme.com")
    assert domains(result) == {"www.acme.com", "dev.acme.com"}


# --- DNS ------------------------------------------------------------------------


def test_spf_dmarc_parsing() -> None:
    txt = join_txt('"v=spf1 include:_spf.google.com " "a:mail.acme.com/24 include:%{i}.x ~all"')
    assert parse_spf(txt) == [("include", "_spf.google.com"), ("a", "mail.acme.com")]
    assert parse_spf("google-site-verification=abc") == []
    assert parse_dmarc("v=DMARC1; p=none; rua=mailto:a@r.acme.net!10m,mailto:b@x.com") == [
        "r.acme.net",
        "x.com",
    ]


async def test_dns_collector(respx_router: respx.MockRouter, http: HttpClient):
    respx_router.get(host="cloudflare-dns.com").mock(
        side_effect=doh_handler(
            {
                ("acme.com", "MX"): {
                    "Status": 0,
                    "Answer": [{"type": 15, "data": "10 mx.acme-mail.net."}],
                },
                ("acme.com", "NS"): {"Status": 0, "Answer": [{"type": 2, "data": "ns1.acme.com."}]},
                ("acme.com", "TXT"): {
                    "Status": 0,
                    "Answer": [{"type": 16, "data": '"v=spf1 include:spf.acme-mailer.com ~all"'}],
                },
                ("_dmarc.acme.com", "TXT"): {
                    "Status": 0,
                    "Answer": [{"type": 16, "data": '"v=DMARC1; rua=mailto:d@dmarcian.com"'}],
                },
            }
        )
    )
    result = await DnsCollector(http).run("acme.com")
    assert result.ok
    assert domains(result) == {
        "mx.acme-mail.net",
        "ns1.acme.com",
        "spf.acme-mailer.com",
        "dmarcian.com",
    }


async def test_dns_collector_partial_failure(respx_router: respx.MockRouter, http: HttpClient):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params["type"] == "MX":
            return httpx.Response(
                200, json={"Status": 0, "Answer": [{"type": 15, "data": "10 mx.acme.net."}]}
            )
        return httpx.Response(500)

    respx_router.get(host="cloudflare-dns.com").mock(side_effect=handler)
    result = await DnsCollector(http).run("acme.com")
    assert result.ok
    assert domains(result) == {"mx.acme.net"}
    assert len(result.metadata["errors"]) == 4


async def test_dns_collector_all_queries_fail(respx_router: respx.MockRouter, http: HttpClient):
    respx_router.get(host="cloudflare-dns.com").respond(500)
    result = await DnsCollector(http).run("acme.com")
    assert result.error is not None and "todas as consultas DNS falharam" in result.error


async def test_tld_variants(respx_router: respx.MockRouter, http: HttpClient):
    respx_router.get(host="cloudflare-dns.com").mock(
        side_effect=doh_handler(
            {("acme.net", "NS"): {"Status": 0, "Answer": [{"type": 2, "data": "ns.x.net."}]}}
        )
    )
    collector = TldVariantsCollector(http, tlds=["com", "net", "io"])
    assert collector.candidates("acme.com") == ["acme.io", "acme.net"]
    result = await collector.run("acme.com")
    assert domains(result) == {"acme.net"}


# --- Analytics / WHOIS -----------------------------------------------------------


def test_extract_trackers() -> None:
    html = """
      <script>gtag('config', 'G-ABC123XYZ'); ga('create', 'UA-1234567-2');</script>
      <script>(window,document,'script','dataLayer','GTM-K9X2ZP');</script>
      <script>fbq('init', '123456789012345');</script>
      <ins data-ad-client="ca-pub-1234567890123456"></ins>
    """
    assert extract_trackers(html) == {
        "google_analytics_ua": ["UA-1234567-2"],
        "google_analytics_ga4": ["G-ABC123XYZ"],
        "google_tag_manager": ["GTM-K9X2ZP"],
        "google_adsense": ["ca-pub-1234567890123456"],
        "facebook_pixel": ["123456789012345"],
    }


def test_extract_ga4_from_gtag_loader_only() -> None:
    # forma real vista em sites com gtag: o ID só aparece na URL do loader
    html = '<script async src="https://www.googletagmanager.com/gtag/js?id=G-9T9CFM6WE0"></script>'
    assert extract_trackers(html) == {"google_analytics_ga4": ["G-9T9CFM6WE0"]}


async def test_analytics_redirect_links_and_trackers(
    respx_router: respx.MockRouter, http: HttpClient
):
    respx_router.get("https://acme.com/").respond(
        301, headers={"Location": "https://www.acmebrand.com/"}
    )
    respx_router.get("https://www.acmebrand.com/").respond(
        text='<a href="https://acme.com/sobre">x</a><a href="https://loja.acmeshop.com/">y</a>'
        "<script>'GTM-ABCD12'</script>"
    )
    result = await AnalyticsCollector(http).run("acme.com")
    assert result.ok
    by_domain = {f.domain: f.evidence for f in result.findings}
    assert "redireciona" in by_domain["www.acmebrand.com"]
    assert by_domain["loja.acmeshop.com"] == "link na página inicial"
    assert "acme.com" not in by_domain
    assert result.metadata["trackers"] == {"google_tag_manager": ["GTM-ABCD12"]}


async def test_analytics_falls_back_to_www(respx_router: respx.MockRouter, http: HttpClient):
    respx_router.get("https://acme.com/").mock(side_effect=httpx.ConnectError("recusado"))
    respx_router.get("https://www.acme.com/").respond(text="<html></html>")
    result = await AnalyticsCollector(http).run("acme.com")
    assert result.ok
    assert result.metadata["final_url"] == "https://www.acme.com/"


def test_parse_rdap_keeps_orgs_and_email_domains_only() -> None:
    data = {
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["kind", {}, "text", "org"],
                        ["fn", {}, "text", "Acme S.A."],
                        ["email", {}, "text", "dns@acme-infra.com"],
                    ],
                ],
                "entities": [
                    {
                        "roles": ["administrative"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Pessoa Física"]]],
                    }
                ],
            },
            {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Registrar X"]]]},
        ],
        "nameservers": [{"ldhName": "NS1.ACME-INFRA.COM"}],
        "events": [{"eventAction": "registration", "eventDate": "2010-01-01"}],
    }
    meta, related = parse_rdap(data)
    assert meta["organizations"] == ["Acme S.A."]
    assert meta["registrar"] == "Registrar X"
    assert meta["contact_email_domains"] == ["acme-infra.com"]
    assert meta["nameservers"] == ["ns1.acme-infra.com"]
    assert "Pessoa Física" not in str(meta)
    assert {d for d, _ in related} == {"acme-infra.com", "ns1.acme-infra.com"}


async def test_whois_collector(respx_router: respx.MockRouter, http: HttpClient):
    respx_router.get("https://rdap.org/domain/acme.com").respond(
        json={"nameservers": [{"ldhName": "ns1.acme.com"}, {"ldhName": "ns.provedor.net"}]}
    )
    result = await WhoisCollector(http).run("www.acme.com")
    assert domains(result) == {"ns1.acme.com", "ns.provedor.net"}


async def test_build_collectors_rejects_unknown(http: HttpClient) -> None:
    with pytest.raises(ValueError, match="shodan"):
        build_collectors(http, ["crtsh", "shodan"])


async def test_whois_reports_tld_without_rdap(respx_router: respx.MockRouter, http: HttpClient):
    respx_router.get("https://rdap.org/domain/acmelab.me").respond(404)
    respx_router.get("https://data.iana.org/rdap/dns.json").respond(
        json={"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]]]}
    )
    result = await WhoisCollector(http).run("acmelab.me")
    assert not result.ok
    assert "TLD .me não publica dados RDAP" in (result.error or "")


async def test_whois_404_with_rdap_tld_means_no_record(
    respx_router: respx.MockRouter, http: HttpClient
):
    respx_router.get("https://rdap.org/domain/naoexiste.com").respond(404)
    respx_router.get("https://data.iana.org/rdap/dns.json").respond(
        json={"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}
    )
    result = await WhoisCollector(http).run("naoexiste.com")
    assert "RDAP sem registro para naoexiste.com" in (result.error or "")


async def test_crtsh_insists_on_502_when_client_allows_retries(respx_router: respx.MockRouter):
    route = respx_router.get("https://crt.sh/")
    route.side_effect = [
        httpx.Response(502),
        httpx.Response(502),
        httpx.Response(502),
        httpx.Response(200, json=[{"id": 1, "name_value": "api.acme.com"}]),
    ]
    # o cliente pede só 1 retry; o crt.sh eleva para CRTSH_RETRIES
    async with HttpClient(retries=1, backoff=0.0) as client:
        result = await CrtShCollector(client).run("acme.com")
    assert result.ok
    assert domains(result) == {"api.acme.com"}
    assert route.call_count == 4


async def test_crtsh_keeps_zero_retries_in_replay_mode(
    respx_router: respx.MockRouter, http: HttpClient
):
    route = respx_router.get("https://crt.sh/").respond(502)
    result = await CrtShCollector(http).run("acme.com")  # fixture: retries=0
    assert not result.ok
    assert route.call_count == 1


async def test_crtsh_only_runs_by_default_when_org_is_given(http: HttpClient) -> None:
    without_org = {c.name for c in build_collectors(http)}
    with_org = {c.name for c in build_collectors(http, org="Acme S.A.")}
    explicit = {c.name for c in build_collectors(http, ["crtsh"])}
    assert "crtsh" not in without_org
    assert "certspotter" in without_org  # os logs de CT continuam cobertos
    assert "crtsh" in with_org
    assert explicit == {"crtsh"}
