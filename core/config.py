"""Configuração via variáveis de ambiente / arquivo .env (nunca chaves no código)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

DEFAULT_MODEL = "claude-opus-5-5"


class MissingApiKeyError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str | None
    model: str
    certspotter_api_key: str | None
    # modelo compatível com OpenAI (Ollama local ou API com plano gratuito)
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_api_key: str | None = None

    def require_anthropic_key(self) -> str:
        if not self.anthropic_api_key:
            raise MissingApiKeyError(
                "ANTHROPIC_API_KEY não configurada. Defina a variável de ambiente ou "
                "crie um arquivo .env (veja .env.example). Sem a API do Claude: "
                "--llm openai (Ollama local, grátis), --llm manual (cole num chat) "
                "ou --no-llm (só heurística)."
            )
        return self.anthropic_api_key


def _env(name: str) -> str | None:
    return os.getenv(f"CERBERUS_{name}") or None


def load_settings() -> Settings:
    load_dotenv()
    return Settings(
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY") or None,
        model=_env("MODEL") or DEFAULT_MODEL,
        certspotter_api_key=os.getenv("CERTSPOTTER_API_KEY") or None,
        llm_base_url=_env("LLM_BASE_URL"),
        llm_model=_env("LLM_MODEL"),
        llm_api_key=_env("LLM_API_KEY"),
    )
