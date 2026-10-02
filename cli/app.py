"""CLI do Cerberus. Use apenas em domínios que você tem autorização para investigar."""

from __future__ import annotations

import asyncio
import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from cli.banner import render_banner
from cli.render import DEFAULT_MAX_ROWS, render_report, render_traffic, safe
from collectors import ALL_COLLECTORS, DEFAULT_COLLECTORS, build_collectors, default_collectors
from core.config import MissingApiKeyError, Settings, load_settings
from core.http_client import HttpClient
from core.llm import (
    Analyzer,
    ClaudeAnalyzer,
    LLMAnalysisError,
    build_manual_prompt,
    create_anthropic_client,
    parse_verdict_text,
)
from core.openai_compat import DEFAULT_BASE_URL, DEFAULT_MODEL, OpenAICompatAnalyzer
from core.pipeline import (
    MAX_REVIEW,
    apply_review,
    collect_and_classify,
    normalize_target,
    select_for_review,
)
from core.pipeline import analyze as run_analysis
from core.replay import ReplayTransport, rules_from_har
from core.traffic import TrafficRecorder, load_har
from core.version import VERSION
from models import AnalysisReport

app = typer.Typer(
    help="Cerberus OSINT — descoberta horizontal de domínios (coleta passiva + revisão por IA).",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
console = Console()
err_console = Console(stderr=True)


class OutputFormat(StrEnum):
    table = "table"
    json = "json"


class LLMChoice(StrEnum):
    auto = "auto"  # claude se houver chave; senão openai se configurado; senão nenhum
    claude = "claude"
    openai = "openai"  # Ollama local ou API compatível com OpenAI
    manual = "manual"  # gera o prompt para colar num chat; veja apply-verdict
    nenhum = "nenhum"


def resolve_llm(choice: LLMChoice, settings: Settings, replay: bool) -> LLMChoice:
    if choice is not LLMChoice.auto:
        return choice
    if settings.anthropic_api_key or replay:
        return LLMChoice.claude
    if settings.llm_base_url:
        return LLMChoice.openai
    return LLMChoice.nenhum


def manual_paths(target: str, directory: Path) -> tuple[Path, Path]:
    stem = f"revisao-{target}"
    return directory / f"{stem}.prompt.txt", directory / f"{stem}.relatorio.json"


def _emit(
    report: AnalysisReport,
    fmt: OutputFormat,
    output: Path | None,
    verbose: bool,
    banner: bool = True,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> None:
    if fmt is OutputFormat.json:
        rendered = report.model_dump_json(indent=2)
        if output:
            output.write_text(rendered, encoding="utf-8")
        else:
            typer.echo(rendered)
    elif output:
        with output.open("w", encoding="utf-8") as fh:
            # arquivo: relatório completo, sem limite de linhas
            plain = Console(file=fh, width=140, color_system=None)
            render_report(report, plain, verbose, max_rows=None)
    else:
        # o banner só aparece na tabela do terminal: JSON e arquivos ficam limpos
        if banner:
            render_banner(console)
        render_report(report, console, verbose, max_rows=max_rows)
    if output:
        err_console.print(f"{len(report.matches)} domínios salvos em {safe(output)}")


def _csv(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _show_version(value: bool) -> None:
    if value:
        typer.echo(f"cerberus-osint {VERSION}")
        raise typer.Exit()


def _prepare_output(*paths: Path | None) -> None:
    """Cria as pastas de saída antes da análise: um caminho inválido falha logo,
    em vez de derrubar a ferramenta depois de toda a coleta."""
    for path in paths:
        if path is None:
            continue
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            err_console.print(
                f"[red]Erro:[/] não foi possível criar a pasta de {safe(path)}: {safe(exc)}"
            )
            raise typer.Exit(2) from exc


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_show_version, is_eager=True, help="Mostra a versão"),
    ] = False,
) -> None:
    """Cerberus OSINT."""


async def _run(
    domain: str,
    *,
    settings: Settings,
    collector_names: list[str],
    org: str | None,
    tlds: list[str] | None,
    third_party: frozenset[str],
    llm: LLMChoice,
    replay: ReplayTransport | None,
    request_timeout: float,
    recorder: TrafficRecorder | None = None,
    manual_dir: Path = Path(),
    max_review: int = MAX_REVIEW,
) -> AnalysisReport:
    hooks = recorder.hooks if recorder else None
    async with HttpClient(
        timeout=request_timeout,
        retries=0 if replay else 2,
        transport=replay,
        event_hooks=hooks,
        public_only=replay is None,  # SSRF: coletores só falam com endereços públicos
    ) as http:
        collectors = build_collectors(
            http,
            collector_names,
            org=org,
            tlds=tlds,
            certspotter_key=settings.certspotter_api_key,
            whois_port43=replay is None,  # o replay só cobre HTTP: nada de rede real
            public_only=replay is None,
        )
        if llm is LLMChoice.nenhum:
            return await run_analysis(domain, collectors, None, third_party)

        if llm is LLMChoice.manual:
            raw, report = await collect_and_classify(domain, collectors, third_party)
            prompt_path, report_path = manual_paths(report.target, manual_dir)
            to_review = select_for_review(report, max_review)
            prompt_path.write_text(build_manual_prompt(raw, to_review), encoding="utf-8")
            report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            report.warnings.append(
                f"modo manual: cole {prompt_path} em um chat, salve a resposta em um arquivo "
                f"e rode: python main.py apply-verdict {report_path} resposta.txt"
            )
            return report

        if llm is LLMChoice.openai:
            # cliente próprio: no --replay as fontes vêm do arquivo, mas o modelo
            # (ex.: Ollama local) é chamado de verdade; o tráfego segue no HAR
            async with HttpClient(retries=1, event_hooks=hooks) as llm_http:
                analyzer: Analyzer = OpenAICompatAnalyzer(
                    llm_http,
                    model=settings.llm_model or DEFAULT_MODEL,
                    base_url=settings.llm_base_url or DEFAULT_BASE_URL,
                    api_key=settings.llm_api_key,
                )
                return await run_analysis(domain, collectors, analyzer, third_party, max_review)

        if replay is not None:
            # replay: o Claude também responde a partir do arquivo gravado
            client = create_anthropic_client(
                "replay-offline", transport=replay, max_retries=0, event_hooks=hooks
            )
        else:
            client = create_anthropic_client(settings.require_anthropic_key(), event_hooks=hooks)
        async with client:
            analyzer = ClaudeAnalyzer(client, settings.model)
            return await run_analysis(domain, collectors, analyzer, third_party, max_review)


@app.command()
def analyze(
    domain: Annotated[str, typer.Argument(help="ex.: example.com ou https://www.example.com")],
    org: Annotated[
        str | None, typer.Option(help='Organização nos certificados (ex.: "Empresa S.A.")')
    ] = None,
    collectors: Annotated[
        str | None,
        typer.Option(
            help=f"Coletores separados por vírgula (padrão: {','.join(DEFAULT_COLLECTORS)}; "
            f"crtsh entra com --org; todos: {','.join(ALL_COLLECTORS)})"
        ),
    ] = None,
    exclude: Annotated[str | None, typer.Option(help="Coletores a excluir")] = None,
    tlds: Annotated[
        str | None, typer.Option(help="TLDs para testar variações (ex.: com,net,io)")
    ] = None,
    third_party: Annotated[
        str | None, typer.Option(help="Domínios extras a tratar como terceiros")
    ] = None,
    llm: Annotated[
        LLMChoice,
        typer.Option(
            help="Quem revisa a lista: claude (API paga), openai (Ollama local/API "
            "compatível), manual (prompt para colar num chat), nenhum (só heurística). "
            "auto: claude se houver chave; senão openai se configurado; senão nenhum"
        ),
    ] = LLMChoice.auto,
    no_llm: Annotated[bool, typer.Option("--no-llm", help="Atalho para --llm nenhum")] = False,
    manual_dir: Annotated[
        Path, typer.Option(help="Pasta dos arquivos do modo manual", file_okay=False)
    ] = Path(),
    replay: Annotated[
        Path | None,
        typer.Option(
            help="Modo offline: responde a partir de um arquivo JSON gravado, sem rede",
            exists=True,
            dir_okay=False,
        ),
    ] = None,
    fmt: Annotated[OutputFormat, typer.Option("--format", "-f")] = OutputFormat.table,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Arquivo de saída")] = None,
    timeout: Annotated[float, typer.Option(help="Timeout por requisição (s)")] = 20.0,
    har: Annotated[
        Path | None,
        typer.Option(help="Grava todo o tráfego HTTP em um arquivo .har (chaves mascaradas)"),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Mostra evidências")] = False,
    max_review: Annotated[
        int,
        typer.Option(help="Máximo de candidatos enviados à revisão por IA (os mais fortes)", min=1),
    ] = MAX_REVIEW,
    no_banner: Annotated[
        bool, typer.Option("--no-banner", help="Não mostra o cabeçalho com os olhos")
    ] = False,
    max_rows: Annotated[
        int,
        typer.Option(help="Máximo de linhas por tabela no terminal (0 = todas)", min=0),
    ] = DEFAULT_MAX_ROWS,
) -> None:
    """Analisa um domínio e lista domínios relacionados, filtrando falsos positivos."""
    settings = load_settings()
    choice = resolve_llm(LLMChoice.nenhum if no_llm else llm, settings, replay is not None)
    if choice is LLMChoice.claude and replay is None:
        try:
            settings.require_anthropic_key()
        except MissingApiKeyError as exc:
            err_console.print(f"[red]Erro:[/] {safe(exc)}")
            raise typer.Exit(2) from exc
    if llm is LLMChoice.auto and choice is LLMChoice.nenhum and not no_llm:
        err_console.print(
            "[yellow]Sem ANTHROPIC_API_KEY nem CERBERUS_LLM_BASE_URL: usando só a heurística."
            "[/] Alternativas grátis: --llm openai (Ollama) ou --llm manual."
        )

    # no modo manual, os arquivos vão para dentro de manual_dir
    manual_file = manual_dir / "revisao.txt" if choice is LLMChoice.manual else None
    _prepare_output(output, har, manual_file)
    exclude_set = set(_csv(exclude))
    names = [n for n in (_csv(collectors) or default_collectors(org)) if n not in exclude_set]
    if not names:
        err_console.print("[red]Erro:[/] nenhum coletor selecionado")
        raise typer.Exit(2)

    try:
        normalize_target(domain)
        transport = ReplayTransport.from_file(replay) if replay else None
        recorder = TrafficRecorder() if har else None
        try:
            with console.status("Coletando dados…", spinner="dots"):
                report = asyncio.run(
                    _run(
                        domain,
                        settings=settings,
                        collector_names=names,
                        org=org,
                        tlds=_csv(tlds) or None,
                        third_party=frozenset(_csv(third_party)),
                        llm=choice,
                        replay=transport,
                        request_timeout=timeout,
                        recorder=recorder,
                        manual_dir=manual_dir,
                        max_review=max_review,
                    )
                )
        finally:
            if har and recorder is not None:
                recorder.save(har)
                err_console.print(f"{len(recorder.entries)} requisições gravadas em {safe(har)}")
    except ValueError as exc:
        err_console.print(f"[red]Erro:[/] {safe(exc)}")
        raise typer.Exit(2) from exc

    _emit(report, fmt, output, verbose, banner=not no_banner, max_rows=max_rows)
    if len(report.collector_errors) == len(names):
        raise typer.Exit(1)


@app.command()
def traffic(
    har: Annotated[Path, typer.Argument(help="Arquivo .har gravado com --har", exists=True)],
    show: Annotated[
        int | None, typer.Option("--show", "-s", help="Mostra a requisição/resposta nº N")
    ] = None,
    body: Annotated[int, typer.Option(help="Caracteres do corpo exibidos com --show")] = 1500,
) -> None:
    """Lista o tráfego gravado, no estilo do HTTP history do Burp."""
    try:
        entries = load_har(har)
    except ValueError as exc:
        err_console.print(f"[red]Erro:[/] {safe(exc)}")
        raise typer.Exit(2) from exc
    if not render_traffic(entries, console, show=show, body_chars=body):
        raise typer.Exit(2)


@app.command("replay-from-har")
def replay_from_har(
    har: Annotated[Path, typer.Argument(help="Arquivo .har gravado com --har", exists=True)],
    output: Annotated[Path, typer.Argument(help="Arquivo de replay (.json) a criar")],
) -> None:
    """Converte um tráfego real gravado em um cenário offline para --replay."""
    try:
        rules = rules_from_har(load_har(har))
    except ValueError as exc:
        err_console.print(f"[red]Erro:[/] {safe(exc)}")
        raise typer.Exit(2) from exc
    _prepare_output(output)
    output.write_text(
        json.dumps({"rules": rules}, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    err_console.print(f"{len(rules)} regras gravadas em {safe(output)}")


@app.command("apply-verdict")
def apply_verdict_cmd(
    report_file: Annotated[
        Path, typer.Argument(help="revisao-<domínio>.relatorio.json do --llm manual", exists=True)
    ],
    answer: Annotated[
        Path, typer.Argument(help="Arquivo com a resposta copiada do chat", exists=True)
    ],
    model: Annotated[
        str | None, typer.Option(help='Qual chat/modelo respondeu (ex.: "claude.ai")')
    ] = None,
    fmt: Annotated[OutputFormat, typer.Option("--format", "-f")] = OutputFormat.table,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Arquivo de saída")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Mostra evidências")] = False,
    no_banner: Annotated[
        bool, typer.Option("--no-banner", help="Não mostra o cabeçalho com os olhos")
    ] = False,
    max_rows: Annotated[
        int,
        typer.Option(help="Máximo de linhas por tabela no terminal (0 = todas)", min=0),
    ] = DEFAULT_MAX_ROWS,
) -> None:
    """Aplica a resposta de um chat (modo manual) ao relatório heurístico."""
    _prepare_output(output)
    try:
        report = AnalysisReport.model_validate_json(report_file.read_text(encoding="utf-8"))
    except ValueError as exc:  # inclui ValidationError do Pydantic
        err_console.print(
            f"[red]Erro:[/] {safe(report_file)} não é um relatório do Cerberus válido "
            "(gere outro com --llm manual)"
        )
        raise typer.Exit(2) from exc
    try:
        verdict = parse_verdict_text(answer.read_text(encoding="utf-8"))
    except LLMAnalysisError as exc:
        err_console.print(f"[red]Erro:[/] {safe(exc)}")
        raise typer.Exit(2) from exc
    report.warnings = [w for w in report.warnings if not w.startswith("modo manual:")]
    reviewed = apply_review(report, verdict, "manual", model)
    _emit(reviewed, fmt, output, verbose, banner=not no_banner, max_rows=max_rows)
