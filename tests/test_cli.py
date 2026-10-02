from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from cli.app import LLMChoice, app, resolve_llm
from core.config import Settings
from models import AnalysisReport
from tests.conftest import ACME_FIXTURE

runner = CliRunner()
REPLAY = ["--replay", str(ACME_FIXTURE), "--org", "Acme Corp S.A."]


def test_missing_api_key_stops_with_friendly_message() -> None:
    result = runner.invoke(app, ["analyze", "acmecorp.com.br", "--llm", "claude"])
    assert result.exit_code == 2
    assert "ANTHROPIC_API_KEY" in result.output
    # aponta as alternativas gratuitas
    assert "--llm openai" in result.output
    assert "--llm manual" in result.output


def test_auto_llm_picks_what_is_available() -> None:
    def settings(**kw: str | None) -> Settings:
        return Settings(anthropic_api_key=None, model="m", certspotter_api_key=None, **kw)

    assert resolve_llm(LLMChoice.auto, settings(), replay=False) is LLMChoice.nenhum
    ollama = settings(llm_base_url="http://localhost:11434/v1")
    assert resolve_llm(LLMChoice.auto, ollama, replay=False) is LLMChoice.openai
    with_key = Settings(anthropic_api_key="k", model="m", certspotter_api_key=None)
    assert resolve_llm(LLMChoice.auto, with_key, replay=False) is LLMChoice.claude
    assert resolve_llm(LLMChoice.manual, with_key, replay=False) is LLMChoice.manual


def test_replay_heuristic_table() -> None:
    result = runner.invoke(app, ["analyze", "acmecorp.com.br", *REPLAY, "--no-llm"])
    assert result.exit_code == 0, result.output
    assert "Subdomínios (6)" in result.output
    assert "loja.acmecorp.com.br" in result.output
    assert "heurística" in result.output


def test_replay_with_claude_json_file(tmp_path: Path) -> None:
    out = tmp_path / "resultado.json"
    result = runner.invoke(
        app, ["analyze", "acmecorp.com.br", *REPLAY, "--format", "json", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    report = AnalysisReport.model_validate_json(out.read_text(encoding="utf-8"))
    assert report.analyzer == "claude"
    assert {fp.domain for fp in report.false_positives} == {"acmecorp.net", "www.instagram.com"}


def test_replay_table_shows_false_positives() -> None:
    result = runner.invoke(app, ["analyze", "acmecorp.com.br", *REPLAY, "-v"])
    assert result.exit_code == 0, result.output
    assert "Falsos positivos descartados (2)" in result.output


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["analyze", "não é domínio", "--no-llm"], "domínio inválido"),
        (["analyze", "acme.com", "--no-llm", "--collectors", "shodan"], "coletores desconhecidos"),
        (
            ["analyze", "acme.com", "--no-llm", "--collectors", "dns", "--exclude", "dns"],
            "nenhum coletor",
        ),
    ],
)
def test_invalid_input(args: list[str], message: str) -> None:
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert message in result.output
