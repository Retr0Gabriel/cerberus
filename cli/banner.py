"""Cabeçalho da ferramenta: os "evil eyes" em vermelho e o nome CERBERUS.

A arte fica em `assets/banner.txt` (caracteres braille) e é lida em tempo de
execução, então pode ser trocada sem mexer no código. Em terminais mais
estreitos que a arte (ex.: celular), só o nome é exibido, para o desenho não
quebrar em várias linhas.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.text import Text

BANNER_FILE = Path(__file__).resolve().parent.parent / "assets" / "banner.txt"
BLANK = "⠀"  # célula braille vazia: completa as linhas sem desalinhar o desenho
NAME = "C E R B E R U S"
TAGLINE = "estamos de olho em tudo"
STYLE = "bold red"


def load_art(path: Path = BANNER_FILE) -> list[str]:
    """Linhas da arte com a mesma largura; lista vazia se o arquivo não existir."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    lines = text.strip("\n").split("\n")
    width = max((len(line) for line in lines), default=0)
    return [line.ljust(width, BLANK) for line in lines]


def render_banner(console: Console, path: Path = BANNER_FILE) -> None:
    art = load_art(path)
    width = len(art[0]) if art else 0
    if art and console.width >= width:
        for line in art:
            console.print(Text(line, style=STYLE), no_wrap=True, overflow="crop")
        pad = max(0, (width - len(NAME)) // 2)
        tag_pad = max(0, (width - len(TAGLINE)) // 2)
    else:
        pad = tag_pad = 0
    console.print(Text(" " * pad + NAME, style=STYLE))
    console.print(Text(" " * tag_pad + TAGLINE, style="dim red"))
    console.print()
