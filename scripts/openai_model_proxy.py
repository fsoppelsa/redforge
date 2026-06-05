#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import signal
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


UPSTREAM_BASE = os.environ.get("UPSTREAM_BASE", "https://api.openai.com/v1").rstrip("/")
UPSTREAM_API_KEY = os.environ.get("UPSTREAM_API_KEY", "").strip()
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
MODEL_ID = os.environ.get("MODEL_ID", "vllm-inference-2/Qwen3 8B").strip()
UPSTREAM_MODEL_ID = os.environ.get("UPSTREAM_MODEL_ID", "gpt-5.4-mini").strip()
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "300"))
THINK_START = "<think>"
THINK_END = "</think>"
CHAT_RESPONSE_DROP_KEYS = {"obfuscation", "service_tier", "system_fingerprint"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.rstrip("/") == "/v1/models":
            self._send_json(
                {
                    "object": "list",
                    "data": [
                        {
                            "id": MODEL_ID,
                            "object": "model",
                            "created": int(time.time()),
                            "owned_by": "openai",
                        }
                    ],
                }
            )
            return
        if self.path.rstrip("/") == f"/v1/models/{MODEL_ID}":
            self._send_json(
                {
                    "id": MODEL_ID,
                    "object": "model",
                    "created": int(time.time()),
                    "owned_by": "openai",
                }
            )
            return
        self._proxy()

    def do_POST(self):
        self._proxy()

    def do_PUT(self):
        self._proxy()

    def do_PATCH(self):
        self._proxy()

    def do_DELETE(self):
        self._proxy()

    def do_OPTIONS(self):
        self._proxy()

    def log_message(self, fmt, *args):
        return

    def _proxy(self):
        body = self._read_body()
        if body:
            body = self._rewrite_body(body)

        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length"}
        }
        headers["Authorization"] = f"Bearer {UPSTREAM_API_KEY}"
        if body is not None:
            headers["Content-Length"] = str(len(body))

        request = Request(
            f"{UPSTREAM_BASE}{self._upstream_path()}",
            data=body,
            headers=headers,
            method=self.command,
        )
        try:
            with urlopen(request, timeout=REQUEST_TIMEOUT) as response:
                if "text/event-stream" in response.headers.get("Content-Type", ""):
                    self.send_response(getattr(response, "status", response.getcode()))
                    for key, value in response.headers.items():
                        if key.lower() in {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade", "content-length"}:
                            continue
                        self.send_header(key, value)
                    self.end_headers()
                    while True:
                        chunk = response.readline()
                        if not chunk:
                            break
                        self.wfile.write(self._sanitize_stream_chunk(chunk))
                        self.wfile.flush()
                    return

                payload = response.read()
                if self._is_json(response.headers.get("Content-Type", "")):
                    payload = self._sanitize_json_payload(payload)
                self.send_response(getattr(response, "status", response.getcode()))
                for key, value in response.headers.items():
                    if key.lower() in {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade", "content-length"}:
                        continue
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if payload:
                    self.wfile.write(payload)
        except HTTPError as exc:
            payload = exc.read()
            self.send_response(exc.code)
            for key, value in exc.headers.items():
                if key.lower() in {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade", "content-length"}:
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if payload:
                self.wfile.write(payload)
        except URLError as exc:
            self.send_error(502, f"Upstream connection failed: {exc.reason}")

    def _read_body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return None
        return self.rfile.read(length)

    def _rewrite_body(self, body: bytes) -> bytes:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return body

        if isinstance(payload, dict):
            if isinstance(payload.get("model"), str):
                payload["model"] = UPSTREAM_MODEL_ID
            if "max_tokens" in payload and "max_completion_tokens" not in payload:
                payload["max_completion_tokens"] = payload.pop("max_tokens")

        return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def _sanitize_json_payload(self, payload: bytes) -> bytes:
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return payload
        if isinstance(data, dict):
            data = self._sanitize_response_dict(data)
        return json.dumps(data, ensure_ascii=False).encode("utf-8")

    def _sanitize_stream_chunk(self, chunk: bytes) -> bytes:
        if not chunk.startswith(b"data: "):
            return chunk
        data = chunk[6:].strip()
        if not data or data == b"[DONE]":
            return chunk
        try:
            event = json.loads(data)
        except json.JSONDecodeError:
            return chunk
        if isinstance(event, dict):
            event = self._sanitize_response_dict(event, chunk=True)
        return b"data: " + json.dumps(event, ensure_ascii=False).encode("utf-8") + b"\n\n"

    def _sanitize_response_dict(self, payload: dict, *, chunk: bool = False) -> dict:
        payload = dict(payload)
        payload["model"] = MODEL_ID
        for key in CHAT_RESPONSE_DROP_KEYS:
            payload.pop(key, None)
        choices = payload.get("choices")
        if isinstance(choices, list):
            sanitized_choices = []
            for choice in choices:
                if not isinstance(choice, dict):
                    sanitized_choices.append(choice)
                    continue
                choice = dict(choice)
                choice.pop("obfuscation", None)
                message = choice.get("message")
                if isinstance(message, dict):
                    message = dict(message)
                    message.pop("annotations", None)
                    message.pop("refusal", None)
                    content = message.get("content")
                    if isinstance(content, str):
                        message["content"] = content
                    choice["message"] = message
                delta = choice.get("delta")
                if isinstance(delta, dict):
                    delta = dict(delta)
                    delta.pop("annotations", None)
                    delta.pop("refusal", None)
                    choice["delta"] = delta
                sanitized_choices.append(choice)
            payload["choices"] = sanitized_choices
        return payload

    @staticmethod
    def _is_json(content_type: str) -> bool:
        return "application/json" in content_type

    def _upstream_path(self) -> str:
        if self.path == "/v1":
            return ""
        if self.path.startswith("/v1/"):
            return self.path[3:]
        return self.path

    def _send_json(self, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)

    def shutdown(*_args):
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    print(
        f"OpenAI model proxy listening on http://{LISTEN_HOST}:{LISTEN_PORT} -> {UPSTREAM_BASE} as {MODEL_ID}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
