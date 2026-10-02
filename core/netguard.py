"""Proteção contra SSRF: os coletores só falam com endereços públicos da internet.

O alvo controla para onde a página inicial redireciona e para qual IP o próprio
domínio aponta; um WHOIS malicioso controla o servidor que ele "indica". Sem
esta checagem, analisar um domínio hostil poderia fazer a ferramenta acessar
a rede interna de quem a executa (ex.: 169.254.169.254, metadados de nuvem).

A checagem vale para IPs escritos na URL e para nomes que resolvem para IPs
não públicos. Se o nome não puder ser resolvido localmente (ex.: rede que só
sai por proxy), a requisição segue: quem resolve é o proxy, não esta máquina.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket

_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")
RESOLVE_TIMEOUT = 3.0


class BlockedDestinationError(RuntimeError):
    pass


def _is_public_ip(value: str) -> bool | None:
    """True/False se `value` for um IP; None se não for."""
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None
    return ip.is_global and not ip.is_multicast


async def _resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), RESOLVE_TIMEOUT
    )
    return [str(info[4][0]) for info in infos]


class PublicHostGuard:
    """Decide se um host é público, com cache por host."""

    def __init__(self) -> None:
        self._cache: dict[str, str | None] = {}

    async def reason_to_block(self, host: str) -> str | None:
        """Motivo do bloqueio, ou None se o host pode ser acessado."""
        host = host.lower().rstrip(".")
        if host not in self._cache:
            self._cache[host] = await self._check(host)
        return self._cache[host]

    async def _check(self, host: str) -> str | None:
        if host == "localhost" or host.endswith(_BLOCKED_SUFFIXES):
            return f"{host} é um nome de rede local"
        literal = _is_public_ip(host)
        if literal is not None:
            return None if literal else f"{host} é um endereço interno"
        try:
            addresses = await _resolve(host)
        except (OSError, TimeoutError):
            return None  # não resolve aqui (ex.: só via proxy): o proxy decide
        internal = [a for a in addresses if _is_public_ip(a) is False]
        if internal:
            return f"{host} aponta para endereço interno ({internal[0]})"
        return None

    async def ensure_public(self, host: str) -> None:
        reason = await self.reason_to_block(host)
        if reason:
            raise BlockedDestinationError(f"destino bloqueado: {reason}")
