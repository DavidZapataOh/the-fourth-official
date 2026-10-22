"""Demo workload for a confidential container group.

Serves `/healthz` and `/token`, which asks the Secure Key Release sidecar
for a Microsoft Azure Attestation token and returns the sidecar's JSON.
"""

import base64
import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_SKR_URL = "http://localhost:8080/attest/maa"


def make_handler(skr_url: str, maa_endpoint: str) -> type[BaseHTTPRequestHandler]:
    """Build a request handler bound to a sidecar URL and an attestation endpoint."""
    host = maa_endpoint.removeprefix("https://").rstrip("/")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/healthz":
                self._send(200, {"status": "ok"})
            elif self.path == "/token":
                self._token()
            else:
                self._send(404, {"error": "not found"})

        def _token(self):
            body = json.dumps(
                {
                    "maa_endpoint": host,
                    "runtime_data": base64.b64encode(os.urandom(16)).decode(),
                }
            ).encode()
            request = urllib.request.Request(
                skr_url, data=body, headers={"Content-Type": "application/json"}
            )
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    self._send(response.status, json.load(response))
            except urllib.error.HTTPError as error:
                self._send(502, {"error": f"sidecar returned {error.code}"})
            except (OSError, ValueError) as error:
                self._send(502, {"error": f"sidecar unreachable: {error}"})

        def _send(self, status: int, payload: dict):
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


if __name__ == "__main__":
    handler = make_handler(os.environ.get("SKR_URL", DEFAULT_SKR_URL), os.environ["MAA_ENDPOINT"])
    ThreadingHTTPServer(("0.0.0.0", 8080), handler).serve_forever()
