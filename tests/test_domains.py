import pytest

from core.domains import is_subdomain_of, normalize, registered_domain
from core.providers import is_third_party


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Empresa.com.br", "empresa.com.br"),
        ("https://www.empresa.com.br/path?x=1", "www.empresa.com.br"),
        ("*.api.empresa.com", "api.empresa.com"),
        ("ti@empresa.com.br", "empresa.com.br"),
        ("empresa.com.:443", "empresa.com"),
        ("_dmarc.empresa.com", "_dmarc.empresa.com"),
        ("invalido..empresa.com", None),
        ("192.168.0.1", None),
        ("localhost", None),
        ("-ruim.com", None),
        ("", None),
        (None, None),
    ],
)
def test_normalize(raw: str | None, expected: str | None) -> None:
    assert normalize(raw) == expected


def test_normalize_idn_to_punycode() -> None:
    result = normalize("açaí.com.br")
    assert result is not None
    assert result.startswith("xn--")
    assert result.endswith(".com.br")


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("api.loja.empresa.com.br", "empresa.com.br"),
        ("empresa.com.br", "empresa.com.br"),
        ("www.empresa.co.uk", "empresa.co.uk"),
        ("a.b.empresa.io", "empresa.io"),
    ],
)
def test_registered_domain(name: str, expected: str) -> None:
    assert registered_domain(name) == expected


def test_is_subdomain_of() -> None:
    assert is_subdomain_of("api.empresa.com", "empresa.com")
    assert is_subdomain_of("empresa.com", "empresa.com")
    assert not is_subdomain_of("outraempresa.com", "empresa.com")


@pytest.mark.parametrize(
    "domain",
    ["aspmx.l.google.com", "ag.dmarcian.com", "ns-12.awsdns-01.com", "x.cloudfront.net"],
)
def test_known_third_party(domain: str) -> None:
    assert is_third_party(domain)


def test_third_party_extra_and_negative() -> None:
    assert not is_third_party("acmepay.com.br")
    assert is_third_party("mail.parceiro.com", frozenset({"parceiro.com"}))
