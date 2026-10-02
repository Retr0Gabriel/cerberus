"""Domínios de provedores (e-mail, DNS, CDN, nuvem, analytics, redes sociais)
que aparecem nos dados coletados mas NÃO pertencem à empresa-alvo.

Serve de pré-classificação barata; o Claude faz a correlação final."""

from __future__ import annotations

import re

from core.domains import registered_domain

KNOWN_THIRD_PARTY = frozenset(
    {
        # e-mail
        "google.com", "googlemail.com", "gmail.com", "outlook.com", "office365.com",
        "microsoft.com", "zoho.com", "protonmail.ch", "mimecast.com", "pphosted.com",
        "sendgrid.net", "mailgun.org", "amazonses.com", "mandrillapp.com", "mcsv.net",
        "sparkpostmail.com", "mailchimp.com", "hubspot.com", "salesforce.com",
        "zendesk.com", "freshdesk.com", "rdstation.com.br",
        # relatórios DMARC
        "dmarcian.com", "valimail.com", "agari.com", "easydmarc.com", "uriports.com",
        "dmarcanalyzer.com", "redsift.cloud", "postmarkapp.com", "powerdmarc.com",
        # DNS / registrars
        "dns.br", "registro.br", "domaincontrol.com", "cloudflare.com",
        "azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info",
        "nsone.net", "ultradns.net", "dnsmadeeasy.com", "googledomains.com",
        "locaweb.com.br", "hostgator.com.br", "kinghost.net", "uolhost.com.br",
        # CDN / nuvem / hospedagem
        "cloudflare.net", "akamai.net", "akamaiedge.net", "edgekey.net",
        "fastly.net", "cloudfront.net", "amazonaws.com", "azurewebsites.net",
        "azureedge.net", "herokuapp.com", "vercel.app", "netlify.app",
        "github.io", "googleusercontent.com", "digitalocean.com", "linode.com",
        "hetzner.com", "ovh.net", "wixdns.net", "shopify.com", "myshopify.com",
        "jsdelivr.net", "unpkg.com", "gstatic.com", "googleapis.com",
        # analytics / marketing
        "google-analytics.com", "googletagmanager.com", "doubleclick.net",
        "googlesyndication.com", "hotjar.com", "facebook.net", "clarity.ms",
        # redes sociais e links comuns
        "facebook.com", "instagram.com", "linkedin.com", "twitter.com", "x.com",
        "youtube.com", "tiktok.com", "wa.me", "whatsapp.com", "apple.com",
    }
)  # fmt: skip

# serviços de estacionamento/revenda de domínios: um domínio com NS deles está
# parado ou à venda e, numa variação de TLD, quase nunca pertence ao alvo
PARKING_NS = frozenset(
    {
        "sedoparking.com", "parkingcrew.net", "bodis.com", "above.com",
        "dan.com", "afternic.com", "hugedomains.com",
    }
)  # fmt: skip

_THIRD_PARTY_PATTERNS = (re.compile(r"^awsdns-\d+\.(com|net|org|co\.uk)$"),)


def is_third_party(domain: str, extra: frozenset[str] = frozenset()) -> bool:
    reg = registered_domain(domain)
    if reg in KNOWN_THIRD_PARTY or reg in extra:
        return True
    return any(p.match(reg) for p in _THIRD_PARTY_PATTERNS)
