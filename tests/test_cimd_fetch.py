"""The real metadata-document download: pinned address, size cap, no redirects, status, cache time, JSON."""
from __future__ import annotations

import asyncio
import gzip

import httpx
import pytest

import mcp_server_auth as msa

URL = "https://agent.example.com/oauth/client.json"
DOC = b'{"client_id": "https://agent.example.com/oauth/client.json", "redirect_uris": ["http://127.0.0.1/cb"]}'
PUBLIC_IP = "93.184.216.34"


class Body(httpx.AsyncByteStream):
    """A response body that arrives over the wire (optionally slowly), like a real server's."""

    def __init__(self, data=b"", pause=0.0):
        self.data, self.pause = data, pause

    async def __aiter__(self):
        for i in range(0, max(len(self.data), 1), 4096):
            if self.pause:
                await asyncio.sleep(self.pause)
            yield self.data[i:i + 4096]


def answer(status, content=b"", headers=None, pause=0.0):
    return httpx.Response(status, headers=headers, stream=Body(content, pause))


@pytest.fixture
def serve(monkeypatch):
    """serve(response) makes the next download answer with that httpx.Response; requests are recorded."""
    real = httpx.AsyncClient
    holder = {"requests": []}

    async def pinned(*_):
        return holder.get("ip", PUBLIC_IP)

    def answer(req):
        holder["requests"].append(req)
        return holder["resp"]

    monkeypatch.setattr(msa, "_pinned_address", pinned)
    monkeypatch.setattr(msa.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(answer), **kw))

    def set_response(resp, ip=PUBLIC_IP):
        holder["resp"], holder["ip"] = resp, ip
        return holder["requests"]
    return set_response


def fetch():
    return asyncio.run(msa.fetch_client_document(URL))


def test_connects_to_the_checked_address_with_the_real_host_name(serve):
    """No second DNS lookup: the request goes to the pinned IP; Host and TLS name stay the vendor's."""
    seen = serve(answer(200, DOC))
    fetch()
    req = seen[0]
    assert req.url.host == PUBLIC_IP and req.url.path == "/oauth/client.json"
    assert req.headers["host"] == "agent.example.com"
    assert req.extensions["sni_hostname"] == "agent.example.com"
    assert req.headers["accept-encoding"] == "identity"


def test_a_slow_server_hits_one_overall_deadline(serve, monkeypatch):
    """httpx's timeout is per read: a byte every few seconds would never trip it."""
    monkeypatch.setattr(msa, "CIMD_TIMEOUT_SECONDS", 0.3)
    serve(answer(200, DOC + b" " * 9000, pause=0.2))     # three chunks, 0.2 s apart
    with pytest.raises(ValueError, match="took too long"):
        fetch()


@pytest.mark.parametrize("header,seconds", [
    ({"cache-control": "public, max-age=120"}, 120),
    ({"cache-control": "max-age=5"}, msa.CIMD_MIN_CACHE_SECONDS),
    ({"cache-control": "max-age=999999"}, msa.CIMD_MAX_CACHE_SECONDS),
    ({}, msa.CIMD_DEFAULT_CACHE_SECONDS),
])
def test_document_and_cache_time(serve, header, seconds):
    serve(answer(200, DOC, header))
    doc, cache = fetch()
    assert doc["client_id"] == URL and cache == seconds


@pytest.mark.parametrize("resp,why", [
    (answer(302, headers={"location": "http://169.254.169.254/latest"}), "answered 302"),
    (answer(500), "answered 500"),
    (answer(200, b"x" * (msa.CIMD_MAX_BYTES + 1)), "too large"),
    (answer(200, b"<html>"), "not JSON"),
    # 10 KB of gzip can unpack to megabytes before a size check on decoded bytes runs
    (answer(200, gzip.compress(DOC), {"content-encoding": "gzip"}), "compressed"),
])
def test_bad_downloads_are_refused(serve, resp, why):
    serve(resp)
    with pytest.raises(ValueError, match=why):
        fetch()


def test_private_hosts_are_refused_before_downloading(serve):
    seen = serve(answer(200, DOC), ip=None)
    with pytest.raises(ValueError, match="not public"):
        fetch()
    assert seen == []


def test_any_private_answer_refuses_the_host(monkeypatch):
    """A name that resolves to one public and one internal address is refused outright."""
    async def answers(host, port, type):  # noqa: A002
        return [(None, None, None, None, ("93.184.216.34", port)), (None, None, None, None, ("10.0.0.5", port))]

    loop = asyncio.new_event_loop()
    monkeypatch.setattr(loop, "getaddrinfo", answers)
    assert loop.run_until_complete(msa._pinned_address("agent.example.com", 443)) is None
    loop.close()


@pytest.mark.parametrize("answer_ip,ok", [
    ("2606:2800:220:1:248:1893:25c8:1946", True),
    ("64:ff9b::5db8:d822", True),        # NAT64 for 93.184.216.34: public
    ("64:ff9b::a00:5", False),           # NAT64 for 10.0.0.5
    ("64:ff9b::a9fe:a9fe", False),       # NAT64 for 169.254.169.254
    ("::127.0.0.1", False),              # IPv4-compatible loopback
    ("::ffff:10.0.0.5", False),
])
def test_ipv6_addresses_that_wrap_a_private_ipv4_are_refused(monkeypatch, answer_ip, ok):
    async def answers(host, port, type):  # noqa: A002
        return [(None, None, None, None, (answer_ip, port))]

    loop = asyncio.new_event_loop()
    monkeypatch.setattr(loop, "getaddrinfo", answers)
    assert (loop.run_until_complete(msa._pinned_address("agent.example.com", 443)) is not None) is ok
    loop.close()
