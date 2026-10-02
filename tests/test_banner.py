from __future__ import annotations

import io
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from cli.app import app
from cli.banner import BANNER_FILE, BLANK, NAME, load_art, render_banner
from tests.conftest import ACME_FIXTURE

runner = CliRunner()
REPLAY = ["--replay", str(ACME_FIXTURE), "--no-llm"]


def capture(width: int) -> str:
    buf = io.StringIO()
    render_banner(Console(file=buf, width=width, color_system=None))
    return buf.getvalue()


def test_art_file_is_braille_with_equal_width_lines() -> None:
    art = load_art()
    assert art, f"arte não encontrada em {BANNER_FILE}"
    assert len({len(line) for line in art}) == 1
    assert all(0x2800 <= ord(ch) <= 0x28FF for line in art for ch in line)


def test_wide_terminal_shows_art_and_name() -> None:
    width = len(load_art()[0])
    out = capture(width)
    assert NAME in out
    assert out.count("\n") > len(load_art())  # arte + nome + frase


def test_narrow_terminal_shows_only_name() -> None:
    out = capture(60)
    assert NAME in out
    assert not any(0x2800 < ord(ch) <= 0x28FF for ch in out)


def test_missing_art_file_still_shows_name(tmp_path: Path) -> None:
    buf = io.StringIO()
    render_banner(Console(file=buf, width=200), path=tmp_path / "nao-existe.txt")
    assert NAME in buf.getvalue()


def test_lines_are_padded_with_blank_braille(tmp_path: Path) -> None:
    art = tmp_path / "a.txt"
    art.write_text("⣿⣿\n⣿\n", encoding="utf-8")
    assert load_art(art) == ["⣿⣿", "⣿" + BLANK]


def test_banner_on_table_but_not_on_json_or_when_disabled() -> None:
    table = runner.invoke(app, ["analyze", "acmecorp.com.br", *REPLAY], terminal_width=200)
    assert table.exit_code == 0, table.output
    assert NAME in table.output
    assert table.output.index(NAME) < table.output.index("Domínio-alvo")  # acima das tabelas

    as_json = runner.invoke(app, ["analyze", "acmecorp.com.br", *REPLAY, "-f", "json"])
    assert NAME not in as_json.output

    off = runner.invoke(app, ["analyze", "acmecorp.com.br", *REPLAY, "--no-banner"])
    assert NAME not in off.output
