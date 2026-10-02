"""Transporte httpx offline: responde a partir de respostas gravadas em JSON.

Usado pelo modo `--replay` da CLI para rodar o pipeline inteiro (coletores e
Claude) sem nenhuma requisição de rede. Formato do arquivo:

    {"rules": [
        {"method": "GET", "url": "https://crt.sh/", "params": {"q": "%.x.com"},
         "status": 200, "json": [...]},
        {"url": "https://exemplo.com/", "text": "<html>...</html>"}
    ]}

`params` é um subconjunto: a regra casa se todos os parâmetros listados
estiverem presentes com o mesmo valor. A primeira regra compatível vence.
`headers` (opcional) vai na resposta, por exemplo `Location` de um redirect.
Requisições sem regra recebem 404 (o coletor falha de forma graciosa).

`rules_from_har` converte um tráfego real gravado com `--har` em regras.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import httpx


class ReplayTransport(httpx.AsyncBaseTransport):
    def __init__(self, rules: Iterable[Mapping[str, Any]]) -> None:
        self.rules = list(rules)
        self.calls: list[httpx.Request] = []
        self._lock = threading.Lock()

    @classmethod
    def from_file(cls, path: str | Path) -> ReplayTransport:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            rules = data["rules"] if isinstance(data, dict) else data
            if not isinstance(rules, list):
                raise TypeError("esperada uma lista de regras")
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(f"arquivo de replay inválido ({path}): {exc}") from exc
        return cls(rules)

    def has_rule_for_host(self, host: str) -> bool:
        return any(httpx.URL(r["url"]).host == host for r in self.rules)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            self.calls.append(request)
        base = str(request.url.copy_with(query=None))
        params = dict(request.url.params)
        for rule in self.rules:
            if rule.get("method", "GET").upper() != request.method:
                continue
            if rule["url"] != base:
                continue
            expected: Mapping[str, Any] = rule.get("params") or {}
            if any(params.get(k) != str(v) for k, v in expected.items()):
                continue
            status = int(rule.get("status", 200))
            headers = rule.get("headers") or {}
            if "json" in rule:
                return httpx.Response(status, json=rule["json"], headers=headers, request=request)
            return httpx.Response(
                status, text=rule.get("text", ""), headers=headers, request=request
            )
        return httpx.Response(404, text=f"sem resposta gravada para {request.url}", request=request)


_KEEP_RESPONSE_HEADERS = ("location", "content-type")


def _rule_from_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    req, resp = entry["request"], entry["response"]
    url = httpx.URL(req["url"])
    rule: dict[str, Any] = {"method": req["method"], "url": str(url.copy_with(query=None))}
    params = dict(url.params)
    if params:
        rule["params"] = params
    rule["status"] = resp["status"]
    headers = {
        h["name"].lower(): h["value"]
        for h in resp.get("headers", [])
        if h["name"].lower() in _KEEP_RESPONSE_HEADERS
    }
    if "location" in headers:
        rule["headers"] = {"location": headers["location"]}
    text = (resp.get("content") or {}).get("text", "")
    if "json" in headers.get("content-type", ""):
        try:
            rule["json"] = json.loads(text)
            return rule
        except ValueError:
            pass
    rule["text"] = text
    return rule


def rules_from_har(entries: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Uma regra por requisição distinta (método + URL + parâmetros).

    Quando a mesma requisição aparece várias vezes (retries), vale a última
    resposta que não seja erro 5xx/429; assim um 502 seguido de 200 grava o 200.
    """
    rules: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in entries:
        if not entry["response"]["status"]:  # falha de rede: não há o que reproduzir
            continue
        rule = _rule_from_entry(entry)
        key = (rule["method"], entry["request"]["url"])
        current = rules.get(key)
        failed = rule["status"] >= 500 or rule["status"] == 429
        if current is None or not failed:
            rules[key] = rule
    return list(rules.values())
