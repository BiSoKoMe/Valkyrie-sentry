"""Prove a rewritten request delivers the FAKE bytes to a real receiver.

test_nyx_rewrite_contract.py already proves apply_rewrite() leaves the right
values sitting on a Python request object. That is necessary but not
sufficient: mitmproxy re-serializes the flow onto the wire from whatever state
the request object holds when it forwards it, and a bug in how a field is
staged (e.g. body changed but framing left pointing at the old length) would
still pass an attribute-equality check while leaking the real bytes or
corrupting delivery. This file closes that gap - a real loopback HTTP server
plays the tracker, receives an actually-sent request, and the assertions read
what THAT SERVER received, not what a Python object claims to hold.

Loopback-only, ephemeral port, no external network - safe to run anywhere.
"""
from __future__ import annotations

import http.client
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from valkyrie.nyx_rewrite import apply_rewrite

RAW_SECRET = b"device_id=REAL-SECRET-ID-0000000000"
FAKE_SHORTER = b"device_id=FAKE"           # deliberately a different length,
                                            # to catch framing bugs that
                                            # attribute equality can't see.


class _CapturingHandler(BaseHTTPRequestHandler):
    received: list[dict] = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)
        _CapturingHandler.received.append({
            "path": self.path,
            "body": body,
            "content_length_header": self.headers.get("Content-Length"),
            "x_device_id": self.headers.get("X-Device-Id"),
        })
        self.send_response(200)
        self.end_headers()


class _Server:
    """One real HTTP server on loopback, torn down after each request."""

    def __enter__(self):
        _CapturingHandler.received = []
        self._httpd = HTTPServer(("127.0.0.1", 0), _CapturingHandler)
        self._port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        kwargs={"poll_interval": 0.01}, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._httpd.shutdown()
        self._thread.join(timeout=2)
        self._httpd.server_close()

    @property
    def port(self) -> int:
        return self._port

    @property
    def received(self) -> list[dict]:
        return _CapturingHandler.received


class _WireRequest:
    """A minimal stand-in for mitmproxy's Request: holds mutable state and can
    actually PUT ITSELF ON THE WIRE from whatever state it currently holds -
    the same thing mitmproxy does when it forwards a flow. Content-Length is
    (re)computed from the live body at send time, exactly as a real HTTP
    client does, so a rewrite that changes body length is exercised for real
    instead of assumed correct."""

    def __init__(self, path: str, body: bytes, headers: dict[str, str], *, fail_url: bool = False):
        self.path = path
        self.raw_content = body
        self.headers = dict(headers)
        self._fail_url = fail_url

    @property
    def url(self):
        return self.path

    @url.setter
    def url(self, value):
        if self._fail_url:
            # Simulate the exact failure class the ADR-tracked incident was:
            # the url setter blows up (a malformed rewritten URL), independent
            # of whether the body/header rewrite would have succeeded.
            raise ValueError("malformed rewritten url")
        self.path = value

    def set_content(self, value):
        self.raw_content = value

    def send(self, port: int) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("POST", self.path, body=self.raw_content, headers=self.headers)
            conn.getresponse().read()
        finally:
            conn.close()


def _rewrite_and_send(server: _Server, *, fail_url: bool = False):
    request = _WireRequest("/collect?id=REAL-SECRET-ID-0000000000",
                           RAW_SECRET, {"X-Device-Id": "REAL-SECRET-ID-0000000000"},
                           fail_url=fail_url)
    result = apply_rewrite(
        request, url=request.url, body=request.raw_content, headers=dict(request.headers),
        new_url="/collect?id=FAKE", new_body=FAKE_SHORTER, new_headers={"X-Device-Id": "FAKE"})
    request.send(server.port)
    return result


def test_receiver_gets_the_faked_bytes_not_the_real_secret():
    with _Server() as server:
        result = _rewrite_and_send(server)
        assert result.outcome == "applied"
        assert len(server.received) == 1
        got = server.received[0]
        assert got["body"] == FAKE_SHORTER
        assert got["x_device_id"] == "FAKE"
        assert got["path"] == "/collect?id=FAKE"
        # The framing must match what was ACTUALLY sent, not the original
        # (longer) raw body's length - a stale Content-Length would desync
        # the connection or truncate the body at the receiver.
        assert got["content_length_header"] == str(len(FAKE_SHORTER))
        assert b"REAL-SECRET-ID" not in got["body"]


def test_a_failed_url_rewrite_still_delivers_the_faked_body_and_headers():
    """Partial protection must reach the wire, not just the Python object.

    This is the receiver-side half of the leak this project already found and
    fixed once (nyx_rewrite.py's docstring / the tls_addon.py history): a
    field that could not be rewritten must never take the others down with
    it, and the receiver must actually see the parts that DID get rewritten.
    """
    with _Server() as server:
        result = _rewrite_and_send(server, fail_url=True)
        assert result.outcome == "partial"
        assert result.failed == ("url",)
        got = server.received[0]
        # The url is real - honestly reflected in `result.failed` - but the
        # body and header, which DID rewrite, must reach the tracker as fake.
        assert "REAL-SECRET-ID" in got["path"]
        assert got["body"] == FAKE_SHORTER
        assert got["x_device_id"] == "FAKE"
        assert b"REAL-SECRET-ID" not in got["body"]
