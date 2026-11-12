"""HTTP-проверка не ходит через прокси из окружения.

С HTTP_PROXY/HTTPS_PROXY (на Windows их часто выставляет VPN-клиент) curl_cffi
и httpx отправляли пробу в прокси: замер проверял сеть прокси, а не оператора,
и выглядел правдоподобно. Здесь прокси указывает на закрытый порт: проба через
него падает, напрямую — доходит до локального сервера.
"""
import asyncio
import http.server
import socket
import threading
import types

import pytest

from conftest import load

check_domains = load("check_domains_proxy_mod", "check-domains.py")


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def server(monkeypatch):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    dead = f"http://127.0.0.1:{_closed_port()}"
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                 "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, dead)
    yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()
    httpd.server_close()


def _pool():
    settings = types.SimpleNamespace(
        interface="", verify_ssl=False, timeout_total=5.0,
        headers={}, impersonate="chrome")
    return check_domains.HTTPClientPool(settings)


def test_httpx_ignores_env_proxy(server):
    async def run():
        client = _pool()._new_httpx(False, None)
        try:
            return (await client.get(server)).status_code
        finally:
            await client.aclose()

    assert asyncio.run(run()) == 204


def test_curl_ignores_env_proxy(server):
    if not check_domains.USE_CURL_CFFI:
        pytest.skip("нужен curl_cffi")

    async def run():
        session = _pool()._new_curl(None)
        assert session is not None
        try:
            return (await session.get(server)).status_code
        finally:
            await session.close()

    assert asyncio.run(run()) == 204
