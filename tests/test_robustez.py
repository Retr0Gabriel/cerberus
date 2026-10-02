"""Casos encontrados no teste final antes da publicação."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from cli.app import app
from collectors.base import describe_error
from core.replay import ReplayTransport
from core.version import VERSION
from tests.conftest import ACME_FIXTURE

runner = CliRunner()
REPLAY = ["--replay", str(ACME_FIXTURE), "--no-llm", "--no-banner"]


def test_output_and_har_in_missing_folders_are_created(tmp_path: Path) -> None:
    out = tmp_path / "pasta" / "nova" / "r.json"
    har = tmp_path / "outra" / "t.har"
    result = runner.invoke(
        app,
        ["analyze", "acmecorp.com.br", *REPLAY, "-f", "json", "-o", str(out), "--har", str(har)],
    )
    assert result.exit_code == 0, result.output
    assert out.exists() and har.exists()


def test_traffic_with_malformed_har_gives_friendly_error(tmp_path: Path) -> None:
    bad = tmp_path / "ruim.har"
    bad.write_text('{"log": {}}', encoding="utf-8")
    result = runner.invoke(app, ["traffic", str(bad)])
    assert result.exit_code == 2
    assert "arquivo HAR inválido" in result.output
    assert "Traceback" not in result.output


def test_traffic_show_out_of_range_exits_with_error(tmp_path: Path) -> None:
    har = tmp_path / "t.har"
    runner.invoke(app, ["analyze", "acmecorp.com.br", *REPLAY, "-f", "json", "--har", str(har)])
    result = runner.invoke(app, ["traffic", str(har), "--show", "999"])
    assert result.exit_code == 2
    assert "escolha um número" in result.output


def test_network_error_without_text_is_explained() -> None:
    exc = httpx.ConnectError("", request=httpx.Request("GET", "https://web.archive.org/cdx"))
    message = describe_error(exc)
    assert message.startswith("ConnectError: conexão com web.archive.org falhou sem detalhes")
    assert describe_error(ValueError("x")) == "ValueError: x"


@pytest.mark.parametrize("content", ["isto não é json", '{"sem": "regras"}', '{"rules": 1}'])
def test_invalid_replay_file_is_reported_clearly(tmp_path: Path, content: str) -> None:
    bad = tmp_path / "replay.json"
    bad.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="arquivo de replay inválido"):
        ReplayTransport.from_file(bad)
    result = runner.invoke(app, ["analyze", "acmecorp.com.br", "--no-llm", "--replay", str(bad)])
    assert result.exit_code == 2
    assert "arquivo de replay inválido" in result.output


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"cerberus-osint {VERSION}"
