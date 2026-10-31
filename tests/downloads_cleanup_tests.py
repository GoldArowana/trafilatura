"""Real HTTP response ownership and keep-alive regressions."""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import trafilatura.downloads as dl
from trafilatura.settings import use_config


@pytest.fixture
def local_http(monkeypatch):
    for pool in (dl.HTTP_POOL, dl.NO_CERT_POOL):
        if pool is not None:
            pool.clear()
    monkeypatch.setattr(dl, "HTTP_POOL", None)
    monkeypatch.setattr(dl, "NO_CERT_POOL", None)
    monkeypatch.setattr(dl, "PROXY_URL", None)
    release_tail = threading.Event()
    requests = []
    connections = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            connections.append(self.connection)

        def log_message(self, *_args):
            pass

        def handle(self):
            try:
                super().handle()
            except OSError:
                pass

        def do_GET(self):
            requests.append((self.path, self.client_address[1]))
            self.send_response(200)
            if self.path.startswith("/oversize"):
                chunked = self.path.endswith("chunked")
                if chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                else:
                    self.send_header("Content-Length", str(2**17 + 64))
                self.end_headers()
                first = b"x" * (2**17)
                self.wfile.write(b"20000\r\n" + first + b"\r\n" if chunked else first)
                self.wfile.flush()
                if release_tail.wait(3):
                    tail = b"y" * 64
                    self.wfile.write(b"40\r\n" + tail + b"\r\n0\r\n\r\n" if chunked else tail)
                    self.wfile.flush()
            elif self.path == "/short":
                self.send_header("Content-Length", "100")
                self.end_headers()
                self.wfile.write(b"x")
                self.close_connection = True
            else:
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = False
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01))
    thread.start()
    config = use_config()
    config.set("DEFAULT", "SSRF_PROTECTION", "off")
    config.set("DEFAULT", "MAX_FILE_SIZE", "1024")
    config.set("DEFAULT", "DOWNLOAD_TIMEOUT", "2")
    config.set("DEFAULT", "MAX_REDIRECTS", "0")
    base = f"http://127.0.0.1:{server.server_port}"

    def fetch(path):
        return dl._send_urllib_request(base + path, False, config)

    try:
        yield fetch, base, release_tail, requests
    finally:
        release_tail.set()
        for pool in (dl.HTTP_POOL, dl.NO_CERT_POOL):
            if pool is not None:
                pool.connection_from_url(base).close()
                pool.clear()
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


@pytest.mark.parametrize("mode", ["length", "chunked"])
def test_size_refusal_does_not_poison_next_response(local_http, mode):
    fetch, base, release_tail, requests = local_http
    assert fetch(f"/oversize-{mode}") is None
    pool = dl.HTTP_POOL.connection_from_url(base)
    with ThreadPoolExecutor(max_workers=1) as workers:
        following = workers.submit(fetch, "/ok")
        deadline = time.monotonic() + 1
        while pool.pool.qsize() and not following.done() and time.monotonic() < deadline:
            time.sleep(0.001)
        release_tail.set()
        result = following.result(timeout=3)
    assert result is not None
    assert result.data == b"ok"
    assert requests[0][0] == f"/oversize-{mode}"
    assert requests[1][0] == "/ok"
    assert requests[0][1] != requests[1][1]


def test_complete_responses_keep_reusing_the_connection(local_http):
    fetch, _, _, requests = local_http
    assert fetch("/ok").data == b"ok"
    assert fetch("/ok").data == b"ok"
    assert len(requests) == 2
    assert requests[0][1] == requests[1][1]


def test_short_body_does_not_poison_next_response(local_http):
    fetch, _, _, requests = local_http
    assert fetch("/short") is None
    assert fetch("/ok").data == b"ok"
    assert requests[0][1] != requests[1][1]
