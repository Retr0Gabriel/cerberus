import httpx

from core.replay import ReplayTransport


async def test_replay_matches_method_url_and_param_subset() -> None:
    transport = ReplayTransport(
        [
            {"url": "https://x.test/api", "params": {"a": "1"}, "json": {"regra": 1}},
            {"url": "https://x.test/api", "json": {"regra": 2}},
            {"method": "POST", "url": "https://x.test/api", "status": 500},
        ]
    )
    async with httpx.AsyncClient(transport=transport) as client:
        assert (await client.get("https://x.test/api", params={"a": 1, "b": 2})).json() == {
            "regra": 1
        }
        assert (await client.get("https://x.test/api", params={"a": 9})).json() == {"regra": 2}
        assert (await client.post("https://x.test/api")).status_code == 500
        missing = await client.get("https://x.test/outra")
    assert missing.status_code == 404
    assert len(transport.calls) == 4
