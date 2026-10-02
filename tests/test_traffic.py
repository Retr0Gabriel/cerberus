from __future__ import annotations

from pathlib import Path

import httpx
import respx
from typer.testing import CliRunner

from cli.app import app
from core.http_client import HttpClient
from core.replay import ReplayTransport, rules_from_har
from core.traffic import TrafficRecorder, load_har

runner = CliRunner()


async def test_recorder_captures_each_redirect_hop_and_masks_secrets(
    respx_router: respx.MockRouter, tmp_path: Path
):
    respx_router.get("https://alvo.test/").respond(301, headers={"Location": "https://outro.test/"})
    respx_router.get("https://outro.test/").respond(
        200, text="<html>ok</html>", headers={"Content-Type": "text/html"}
    )
    recorder = TrafficRecorder()
    async with HttpClient(retries=0, event_hooks=recorder.hooks) as http:
        resp = await http.get("https://alvo.test/", headers={"x-api-key": "segredo"})
    assert resp.text == "<html>ok</html>"

    har = tmp_path / "t.har"
    recorder.save(har)
    entries = load_har(har)
    assert [(e["request"]["url"], e["response"]["status"]) for e in entries] == [
        ("https://alvo.test/", 301),
        ("https://outro.test/", 200),
    ]
    assert entries[0]["response"]["redirectURL"] == "https://outro.test/"
    assert entries[1]["response"]["content"]["text"] == "<html>ok</html>"
    assert "segredo" not in har.read_text(encoding="utf-8")


def _entry(url: str, status: int, text: str = "", mime: str = "", location: str = "") -> dict:
    headers = [{"name": "Content-Type", "value": mime}] if mime else []
    if location:
        headers.append({"name": "Location", "value": location})
    return {
        "request": {"method": "GET", "url": url},
        "response": {"status": status, "headers": headers, "content": {"text": text}},
    }


def test_rules_from_har_keeps_last_success_and_redirects() -> None:
    rules = rules_from_har(
        [
            _entry("https://crt.sh/?q=%25.x.com&output=json", 502, "Bad Gateway"),
            _entry(
                "https://crt.sh/?q=%25.x.com&output=json", 200, '[{"id": 1}]', "application/json"
            ),
            _entry("https://x.com/", 301, location="https://www.x.com/"),
            _entry("https://web.archive.org/cdx", 0),  # falha de rede: ignorada
        ]
    )
    assert rules == [
        {
            "method": "GET",
            "url": "https://crt.sh/",
            "params": {"q": "%.x.com", "output": "json"},
            "status": 200,
            "json": [{"id": 1}],
        },
        {
            "method": "GET",
            "url": "https://x.com/",
            "status": 301,
            "headers": {"location": "https://www.x.com/"},
            "text": "",
        },
    ]


async def test_replay_rule_headers_drive_redirects() -> None:
    transport = ReplayTransport(
        [
            {"url": "https://x.com/", "status": 301, "headers": {"location": "https://y.com/"}},
            {"url": "https://y.com/", "text": "destino"},
        ]
    )
    async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
        resp = await client.get("https://x.com/")
    assert str(resp.url) == "https://y.com/"
    assert resp.text == "destino"


def test_traffic_command_lists_like_burp(tmp_path: Path) -> None:
    har = tmp_path / "t.har"
    recorder = TrafficRecorder()
    recorder.entries = [
        {
            "startedDateTime": "2026-01-01T00:00:00+00:00",
            "time": 12.0,
            "request": {
                "method": "GET",
                "url": "https://crt.sh/?q=%25.x.com",
                "httpVersion": "HTTP/1.1",
                "headers": [],
            },
            "response": {
                "status": 200,
                "statusText": "OK",
                "httpVersion": "HTTP/1.1",
                "headers": [],
                "content": {"size": 11, "mimeType": "application/json", "text": '["[a]", 1]'},
            },
        }
    ]
    recorder.save(har)
    listing = runner.invoke(app, ["traffic", str(har)])
    assert listing.exit_code == 0, listing.output
    assert "crt.sh" in listing.output
    assert "200" in listing.output

    detail = runner.invoke(app, ["traffic", str(har), "--show", "1"])
    assert detail.exit_code == 0, detail.output
    assert '["[a]", 1]' in detail.output  # colchetes do corpo não somem como markup


async def test_recorder_keeps_network_failures(respx_router: respx.MockRouter):
    respx_router.get("https://web.archive.org/cdx").mock(
        side_effect=httpx.ConnectError("conexão recusada")
    )
    recorder = TrafficRecorder()
    async with HttpClient(retries=1, backoff=0.0, event_hooks=recorder.hooks) as http:
        try:
            await http.get("https://web.archive.org/cdx")
        except httpx.ConnectError:
            pass
    assert [e["response"]["status"] for e in recorder.entries] == [0, 0]  # 1 + 1 retry
    assert recorder.entries[0]["response"]["_error"] == "ConnectError: conexão recusada"
