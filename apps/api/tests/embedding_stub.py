"""A stub model server speaking the OpenAI embeddings protocol, on
loopback, for the embeddings suites (F6.2, 2026-09-24). Importable, no
tests. Nothing here contacts a real model service.

Vectors are the built-in embedder's first `dims` components, so similar
texts get similar vectors and the MEANING tests read like the real thing;
`drift` reverses them, which is what a different model behind the same
endpoint looks like to the canary.
"""
from __future__ import annotations

import http.server
import json
import threading
import time

from noctornal_api import embedders as E


class StubModel:
    def __init__(self, *, dims: int = 384, model: str = "stub-embed"):
        self.dims = dims
        self.model = model
        self.mode = "ok"
        self.status = 200
        self.delay = 0.0
        self.drift = False
        #: The canary is answered normally whatever `mode` says, so a test
        #: can fail the batches of a pass whose canary check succeeds.
        self.spare_canary = True
        self.requests: list[dict] = []
        self.on_request = None
        self._builtin = E.HashedNgramEmbedder(cache_slots=10_000)
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):  # noqa: N802 - http.server's name
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = {}
                stub.requests.append({"path": self.path, "body": body,
                                      "headers": dict(self.headers.items())})
                if stub.on_request is not None:
                    stub.on_request(body)
                if stub.delay:
                    time.sleep(stub.delay)
                stub.answer(self, body, raw)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return self.server.server_port

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def vector(self, text: str) -> list[float]:
        out = self._builtin.embed_one(text)
        values = list(out.vector or [0.0] * E.EMBED_DIM)[: self.dims]
        if not any(values):
            values[0] = 1.0
        return values[::-1] if self.drift else values

    def texts(self) -> list[str]:
        """Every input text the stub has received, in order."""
        return [t for r in self.requests for t in (r["body"].get("input") or [])]

    def content_requests(self) -> list[dict]:
        """The requests that carried something other than the canary."""
        return [r for r in self.requests
                if any(E.CANARY_TEXT not in t for t in r["body"].get("input") or [])]

    def answer(self, handler, body: dict, raw: bytes) -> None:
        inputs = body.get("input") or []
        data = [{"object": "embedding", "index": i, "embedding": self.vector(t)}
                for i, t in enumerate(inputs)]
        mode = self.mode
        if self.spare_canary and inputs and all(E.CANARY_TEXT in t for t in inputs):
            mode = "ok"
        if mode == "status":
            # Echoes the input, as some model servers do in a 4xx body.
            self._send(handler, self.status, b"bad input: " + raw[:500])
            return
        if mode == "redirect":
            handler.send_response(302)
            handler.send_header("Location", "http://127.0.0.1:9/elsewhere")
            handler.send_header("Content-Length", "0")
            handler.end_headers()
            return
        if mode == "count":
            data = data[:-1]
        elif mode == "dup_index" and data:
            data[-1]["index"] = 0
        elif mode == "nan" and data:
            data[0]["embedding"][0] = float("nan")
        elif mode == "mixed" and len(data) > 1:
            data[1]["embedding"] = data[1]["embedding"][:-1]
        elif mode == "long" and data:
            for entry in data:
                entry["embedding"] = entry["embedding"] + [0.1] * (800 - len(entry["embedding"]))
        elif mode == "notjson":
            self._send(handler, 200, b"<html>not json</html>")
            return
        # Hostile answers (2026-09-25): each once escaped the
        # parser as a Python error, or would have.
        elif mode == "bigint" and data:
            data[0]["embedding"][0] = 10 ** 400        # OverflowError as a float
        elif mode == "huge" and data:
            for entry in data:                         # finite, squares to inf
                entry["embedding"] = [1e308 if i % 2 else -1e308
                                      for i in range(len(entry["embedding"]))]
        elif mode == "zeros" and data:
            data[0]["embedding"] = [0.0] * len(data[0]["embedding"])
        elif mode == "text_value" and data:
            data[0]["embedding"][0] = "0.5"
        elif mode == "nested_value" and data:
            data[0]["embedding"][0] = [0.5]
        elif mode == "deep":
            depth = 100_000                            # RecursionError in json
            self._send(handler, 200, b'{"data":' + b"[" * depth + b"]" * depth + b"}")
            return
        elif mode == "oversize":
            self._send(handler, 200, b"[" + b" " * (17 * 1024 * 1024) + b"]")
            return
        elif mode == "drip":
            handler.send_response(200)
            handler.send_header("Content-Length", "100000")
            handler.end_headers()
            try:
                for _ in range(1000):
                    handler.wfile.write(b" ")
                    handler.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                pass
            return
        payload = json.dumps({"object": "list", "data": data, "model": self.model},
                             allow_nan=True).encode()
        self._send(handler, 200, payload)

    @staticmethod
    def _send(handler, status: int, payload: bytes) -> None:
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        try:
            handler.wfile.write(payload)
        except OSError:
            pass


def meaning_env(stub: StubModel, **overrides) -> dict:
    """A MEANING configuration pointing at the stub. `local=True` declares
    it this host's own model server (MODEL_HOST); without it the loopback
    endpoint is treated as outside this host (MODEL_REMOTE)."""
    local = overrides.pop("local", True)
    env = {E.URL_ENV: stub.url, E.MODEL_ENV: stub.model, E.CEILING_ENV: "RED",
           E.TIMEOUT_ENV: "5"}
    if local:
        env[E.LOCAL_HOST_ENV] = "127.0.0.1"
    env.update({k: v for k, v in overrides.items() if v is not None})
    return env


class NoRoutes:
    """A connection with no egress route rows (2026-09-25). The route
    provider asks for an administrator's row before it falls back, in
    development, to the declared rules alone; these tests hold no database."""

    def execute(self, *_args, **_kwargs):
        return self

    def fetchone(self):
        return None

    def fetchall(self):
        return []
