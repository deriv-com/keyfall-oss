"""The real metadata-document download: size cap, no redirects, status, cache time, JSON."""
from __future__ import annotations

import asyncio

import httpx
import pytest

import mcp_server_auth as msa

URL = "https://agent.example.com/oauth/client.json"
DOC = b'{"client_id": "https://agent.example.com/oauth/client.json", "redirect_uris": ["http://127.0.0.1/cb"]}'


@pytest.fixture
def serve(monkeypatch):
    """serve(response) makes the next download answer with that httpx.Response."""
    real = httpx.AsyncClient
    holder = {}

    async def public(*_):
        return holder.get("public", True)

    monkeypatch.setattr(msa, "_resolves_publicly", public)
    monkeypatch.setattr(msa.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(lambda req: holder["resp"]), **kw))

    def set_response(resp, public=True):
        holder["resp"], holder["public"] = resp, public
    return set_response


def fetch():
    return asyncio.run(msa.fetch_client_document(URL))


@pytest.mark.parametrize("header,seconds", [
    ({"cache-control": "public, max-age=120"}, 120),
    ({"cache-control": "max-age=5"}, msa.CIMD_MIN_CACHE_SECONDS),
    ({"cache-control": "max-age=999999"}, msa.CIMD_MAX_CACHE_SECONDS),
    ({}, msa.CIMD_DEFAULT_CACHE_SECONDS),
])
def test_document_and_cache_time(serve, header, seconds):
    serve(httpx.Response(200, content=DOC, headers=header))
    doc, cache = fetch()
    assert doc["client_id"] == URL and cache == seconds


@pytest.mark.parametrize("resp,why", [
    (httpx.Response(302, headers={"location": "http://169.254.169.254/latest"}), "answered 302"),
    (httpx.Response(500), "answered 500"),
    (httpx.Response(200, content=b"x" * (msa.CIMD_MAX_BYTES + 1)), "too large"),
    (httpx.Response(200, content=b"<html>"), "not JSON"),
])
def test_bad_downloads_are_refused(serve, resp, why):
    serve(resp)
    with pytest.raises(ValueError, match=why):
        fetch()


def test_private_hosts_are_refused_before_downloading(serve):
    serve(httpx.Response(200, content=DOC), public=False)
    with pytest.raises(ValueError, match="not public"):
        fetch()
