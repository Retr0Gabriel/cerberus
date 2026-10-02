"""Normalização e validação de nomes de domínio."""

from __future__ import annotations

import re

# Sufixos públicos de dois níveis mais comuns. Não substitui a Public Suffix
# List completa, mas cobre os casos mais frequentes (principalmente .br).
MULTI_LEVEL_SUFFIXES = frozenset(
    {
        "com.br", "net.br", "org.br", "gov.br", "edu.br", "ind.br", "inf.br",
        "art.br", "adv.br", "eng.br", "med.br", "blog.br", "app.br", "tec.br",
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
        "com.au", "net.au", "org.au", "co.jp", "co.nz", "co.za", "co.in",
        "com.mx", "com.ar", "com.co", "com.pe", "com.cl", "com.uy", "com.py",
        "com.pt", "com.es", "com.cn", "com.tr",
    }
)  # fmt: skip

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://")


def is_valid_domain(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    labels = name.split(".")
    if len(labels) < 2:
        return False
    if not all(_LABEL_RE.match(label) for label in labels):
        return False
    tld = labels[-1]
    # TLD numérico indica IP; underscore só aparece em labels de serviço
    return not tld.isdigit() and "_" not in tld


def normalize(name: str | None) -> str | None:
    """Converte URLs, e-mails, wildcards e IDNs em um nome de domínio limpo.

    Retorna None quando o valor não é um domínio válido.
    """
    if not name:
        return None
    n = str(name).strip().lower()
    n = _SCHEME_RE.sub("", n)
    n = n.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in n:  # e-mail em SAN de certificado, DMARC ou RDAP
        n = n.rsplit("@", 1)[1]
    n = n.split(":", 1)[0].rstrip(".")
    while n.startswith("*."):
        n = n[2:]
    if not n.isascii():
        try:
            n = n.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return n if is_valid_domain(n) else None


def registered_domain(name: str) -> str:
    """'api.loja.empresa.com.br' -> 'empresa.com.br'."""
    labels = name.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_subdomain_of(name: str, root: str) -> bool:
    return name == root or name.endswith("." + root)
