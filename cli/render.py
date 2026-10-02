"""Formatação do relatório com Rich.

Quase tudo o que aparece aqui vem de fora (servidores consultados, o próprio
alvo, o texto do modelo de IA) e passa por `safe`/`clean` antes de ir ao
terminal: sem isso, um dado com `[/]` derrubaria a ferramenta, `[link=...]`
criaria um link falso e sequências ANSI poderiam limpar a tela ou mudar o
título da janela de quem está analisando.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from models import AnalysisReport, Category

SECTIONS: tuple[tuple[Category, str], ...] = (
    ("alvo", "Domínio-alvo"),
    ("subdominio", "Subdomínios"),
    ("relacionado", "Domínios relacionados"),
    ("terceiros", "Infraestrutura de terceiros"),
)
_ANALYZER_LABEL = {
    "claude": "Claude",
    "openai": "modelo compatível com OpenAI",
    "manual": "revisão manual (chat)",
    "heuristica": "heurística",
}
_LABEL_STYLE = {"alta": "green", "media": "yellow", "baixa": "red"}
DEFAULT_MAX_ROWS = 200

# controle C0/C1 (inclui ESC, que inicia as sequências ANSI) e marcas de direção
# bidirecional (usadas para disfarçar texto); \t e \n são mantidos
_UNSAFE_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def clean(value: object) -> str:
    """Texto externo sem caracteres de controle (para usar dentro de `Text`)."""
    return _UNSAFE_RE.sub("", str(value))


def safe(value: object) -> str:
    """Texto externo pronto para strings com marcação do Rich (colchetes literais)."""
    return escape(clean(value))


def render_report(
    report: AnalysisReport,
    console: Console,
    verbose: bool = False,
    max_rows: int | None = DEFAULT_MAX_ROWS,
) -> None:
    """`max_rows` limita as linhas por tabela (None ou 0 = todas)."""
    label = _ANALYZER_LABEL[report.analyzer]
    analyzer = safe(f"{label} ({report.model})" if report.model else label)
    header = f"[bold]{safe(report.target)}[/]  ·  análise: {analyzer}  ·  {report.elapsed_seconds}s"
    body = safe(report.summary) if report.summary else header
    console.print(Panel(body, title=header if report.summary else None))

    for category, title in SECTIONS:
        matches = report.by_category(category)
        if not matches:
            continue
        table = Table(title=f"{title} ({len(matches)})", title_justify="left", expand=True)
        table.add_column("Domínio", style="bold", overflow="fold")
        table.add_column("Confiança", no_wrap=True)
        table.add_column("Fontes", overflow="fold")
        show_detail = verbose or category in ("relacionado", "terceiros")
        if show_detail:
            table.add_column("Motivo / evidência", overflow="fold")
        shown = matches[:max_rows] if max_rows else matches
        for m in shown:
            label = m.confidence_label
            row = [
                safe(m.domain),
                f"[{_LABEL_STYLE[label]}]{label} ({m.confidence:.2f})[/]",
                safe(", ".join(m.sources)),
            ]
            if show_detail:
                detail = m.reasoning or (m.evidence[0] if m.evidence else "")
                if verbose and m.evidence:
                    detail = "\n".join(filter(None, [m.reasoning, *m.evidence]))
                row.append(safe(detail))
            table.add_row(*row)
        if len(shown) < len(matches):
            table.add_row(
                f"[dim]… e mais {len(matches) - len(shown)} (use --max-rows 0, -o ou -f json)[/]"
            )
        console.print(table)

    if report.false_positives:
        table = Table(
            title=f"Falsos positivos descartados ({len(report.false_positives)})",
            title_justify="left",
            expand=True,
        )
        table.add_column("Domínio", style="dim", overflow="fold")
        table.add_column("Motivo", overflow="fold")
        for fp in report.false_positives:
            table.add_row(safe(fp.domain), safe(fp.reason))
        console.print(table)

    counts = ", ".join(f"{k}={v}" for k, v in sorted(report.source_counts.items()))
    console.print(f"[dim]Achados por fonte: {safe(counts) or 'nenhum'}[/]")
    for name, err in sorted(report.collector_errors.items()):
        console.print(f"[yellow]⚠ coletor {safe(name)} falhou:[/] {safe(err)}")
    for warning in report.warnings:
        console.print(f"[yellow]⚠ {safe(warning)}[/]")


def _short(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_traffic(
    entries: list[dict[str, Any]],
    console: Console,
    show: int | None = None,
    body_chars: int = 1500,
) -> bool:
    """Tabela no estilo do HTTP history do Burp; com `show`, o detalhe de uma linha.
    Devolve False se `show` estiver fora do intervalo."""
    if show is not None:
        if not 1 <= show <= len(entries):
            console.print(f"[red]Erro:[/] escolha um número entre 1 e {len(entries)}")
            return False
        _render_exchange(entries[show - 1], console, show, body_chars)
        return True

    table = Table(title=f"Tráfego HTTP ({len(entries)} requisições)", title_justify="left")
    table.add_column("#", justify="right")
    table.add_column("Host", overflow="fold")
    table.add_column("Método")
    table.add_column("URL", overflow="fold")
    table.add_column("Status", justify="right")
    table.add_column("Tamanho", justify="right")
    table.add_column("MIME", overflow="fold")
    table.add_column("Tempo (ms)", justify="right")
    for i, e in enumerate(entries, 1):
        req, resp = e["request"], e["response"]
        parts = urlsplit(req["url"])
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        status = resp["status"]
        style = "green" if 0 < status < 300 else "yellow" if 0 < status < 400 else "red"
        mime = resp.get("_error", "")[:40] or resp["content"]["mimeType"].split(";")[0]
        table.add_row(
            str(i),
            safe(parts.hostname or ""),
            safe(req["method"]),
            safe(_short(path, 70)),
            f"[{style}]{status or 'ERRO'}[/]",
            safe(resp["content"]["size"]),
            safe(mime),
            f"{e['time']:.0f}",
        )
    console.print(table)
    return True


def _render_exchange(e: dict[str, Any], console: Console, n: int, body_chars: int) -> None:
    req, resp = e["request"], e["response"]
    parts = urlsplit(req["url"])
    path = parts.path + (f"?{parts.query}" if parts.query else "")
    req_lines = [f"{req['method']} {path} {req['httpVersion']}"]
    req_lines += [f"{h['name']}: {h['value']}" for h in req["headers"]]
    if req.get("postData"):
        req_lines += ["", _short(req["postData"]["text"], body_chars)]
    resp_lines = [f"{resp['httpVersion']} {resp['status']} {resp['statusText']}"]
    resp_lines += [f"{h['name']}: {h['value']}" for h in resp["headers"]]
    resp_lines += ["", _short(resp["content"]["text"], body_chars)]
    # Text (não markup) e sem caracteres de controle: cabeçalhos e corpo vêm do servidor
    host = safe(parts.hostname or "")
    console.print(Panel(Text(clean("\n".join(req_lines))), title=f"#{n} Request · {host}"))
    console.print(
        Panel(Text(clean("\n".join(resp_lines))), title=f"#{n} Response · {e['time']:.0f} ms")
    )
