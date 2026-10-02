from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from typing import ClassVar

import httpx

from core.http_client import HttpClient
from models import Collected, CollectorResult


def describe_error(exc: BaseException) -> str:
    """Tipo + mensagem; quando a exceção não traz texto (comum em falhas de rede),
    explica o que houve e, se possível, com qual host."""
    text = str(exc).strip()
    if text:
        return f"{type(exc).__name__}: {text}"
    host = ""
    if isinstance(exc, httpx.HTTPError):
        try:
            host = f" com {exc.request.url.host}"
        except RuntimeError:  # exceção sem requisição associada
            pass
    reason = "servidor fora do ar ou rede bloqueada"
    return f"{type(exc).__name__}: conexão{host} falhou sem detalhes ({reason})"


class CollectorError(Exception):
    """Falha de coleta que não vem do httpx (ex.: todas as consultas falharam)."""


class Collector(ABC):
    name: ClassVar[str]
    # peso usado pela heurística (probabilidade de o domínio ser do alvo)
    weight: ClassVar[float] = 0.3
    # timeout total do coletor, além do timeout por requisição do HttpClient
    timeout: ClassVar[float] = 60.0

    def __init__(self, http: HttpClient) -> None:
        self.http = http

    @abstractmethod
    async def collect(self, target: str) -> Collected: ...

    async def run(self, target: str) -> CollectorResult:
        """Executa `collect` com timeout explícito e falha graciosa."""
        start = time.monotonic()
        try:
            out = await asyncio.wait_for(self.collect(target), self.timeout)
        except TimeoutError:
            error = f"timeout após {self.timeout:.0f}s"
        except httpx.HTTPError as exc:
            error = describe_error(exc)
        except (CollectorError, ValueError, KeyError, TypeError, AttributeError) as exc:
            # ValueError cobre JSON inválido; KeyError/TypeError/AttributeError, formato
            # inesperado (ex.: lista de textos onde se esperavam objetos; achado no fuzzing)
            error = describe_error(exc)
        else:
            return CollectorResult(
                name=self.name,
                findings=out.findings,
                metadata=out.metadata,
                elapsed_seconds=time.monotonic() - start,
            )
        return CollectorResult(
            name=self.name, error=error, elapsed_seconds=time.monotonic() - start
        )
