import base64
import importlib.util
import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1] / "app" / "app.py"
spec = importlib.util.spec_from_file_location("aci_attest_app", APP)
assert spec and spec.loader
aci_attest_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aci_attest_app)

MAA = "https://sharedneu.neu.attest.azure.net"


@contextmanager
def serve(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def stub_sidecar(received: list[dict], reply: dict) -> type[BaseHTTPRequestHandler]:
    class Sidecar(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append({"path": self.path, "body": json.loads(body)})
            payload = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            pass

    return Sidecar


@contextmanager
def app_for(skr_url: str) -> Iterator[str]:
    with serve(aci_attest_app.make_handler(skr_url, MAA)) as url:
        yield url


def get(url: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def test_healthz_returns_200():
    with app_for("http://127.0.0.1:9/attest/maa") as url:
        assert get(f"{url}/healthz")[0] == 200


def test_unknown_path_returns_404():
    with app_for("http://127.0.0.1:9/attest/maa") as url:
        assert get(f"{url}/other")[0] == 404


def test_token_passes_sidecar_response_through():
    reply = {"token": "header.payload.signature"}
    with serve(stub_sidecar([], reply)) as sidecar, app_for(f"{sidecar}/attest/maa") as url:
        status, body = get(f"{url}/token")
    assert status == 200
    assert json.loads(body) == reply


def test_token_returns_502_when_sidecar_is_down():
    with app_for("http://127.0.0.1:9/attest/maa") as url:
        status, body = get(f"{url}/token")
    assert status == 502
    assert "error" in json.loads(body)


def test_token_sends_maa_endpoint_in_request_body():
    received: list[dict] = []
    with (
        serve(stub_sidecar(received, {"token": "t"})) as sidecar,
        app_for(f"{sidecar}/attest/maa") as url,
    ):
        get(f"{url}/token")
    assert [r["path"] for r in received] == ["/attest/maa"]
    body = received[0]["body"]
    assert body["maa_endpoint"] == "sharedneu.neu.attest.azure.net"
    assert len(base64.b64decode(body["runtime_data"], validate=True)) == 16
    assert set(body) == {"maa_endpoint", "runtime_data"}


@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_non_get_methods_are_rejected(method):
    with app_for("http://127.0.0.1:9/attest/maa") as url:
        request = urllib.request.Request(f"{url}/token", method=method, data=b"")
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=5)
    assert error.value.code in {405, 501}
