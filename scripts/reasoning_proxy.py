#!/usr/bin/env python3

import json
import os
import re
import signal
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


UPSTREAM_BASE = os.environ.get("UPSTREAM_BASE", "http://127.0.0.1:8000").rstrip("/")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8001"))
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "300"))
THINKING_PLACEHOLDER = os.environ.get("THINKING_PLACEHOLDER", "")
DISPLAY_MODEL_ID = os.environ.get("DISPLAY_MODEL_ID", "").strip()
UPSTREAM_MODEL_ID = os.environ.get("UPSTREAM_MODEL_ID", "").strip()
UPSTREAM_API_KEY = os.environ.get("UPSTREAM_API_KEY", "").strip()
REQUEST_MODEL_ALIASES = {
    alias.strip(): UPSTREAM_MODEL_ID
    for alias in (
        os.environ.get("MODEL_ALIASES", "").split(",")
        + [os.environ.get("INFERENCE_SERVICE_NAME", "")]
    )
    if alias.strip() and UPSTREAM_MODEL_ID
}
MODEL_IDS = [DISPLAY_MODEL_ID] if DISPLAY_MODEL_ID else []

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

THINK_START = "<think>"
THINK_END = "</think>"
THINK_BLOCK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL)
THINK_TAIL_RE = re.compile(r"<think>.*$", re.DOTALL)
LEADING_REASONING_RE = re.compile(
    r"^\s*(?:thought|reasoning|thinking|analysis)\s*:\s*",
    re.IGNORECASE,
)
FINAL_LABEL_RE = re.compile(
    r"^\s*(?:final answer|answer|response)\s*:\s*",
    re.IGNORECASE,
)
LET_ME_THINK_PREFIXES = (
    "let me think",
    "okay, let me think",
    "ok, let me think",
    "i need to think",
    "i should think",
    "i should reason",
    "i need to reason",
)


class ThinkStripper:
    def __init__(self):
        self.in_think = False
        self.buffer = ""

    def feed(self, text):
        self.buffer += text
        visible = []

        while True:
            if self.in_think:
                end_idx = self.buffer.find(THINK_END)
                if end_idx == -1:
                    keep = max(len(THINK_END) - 1, 0)
                    self.buffer = self.buffer[-keep:] if keep else ""
                    break
                self.buffer = self.buffer[end_idx + len(THINK_END):]
                self.in_think = False
                continue

            start_idx = self.buffer.find(THINK_START)
            if start_idx == -1:
                keep = max(len(THINK_START) - 1, 0)
                if keep and len(self.buffer) > keep:
                    visible.append(self.buffer[:-keep])
                    self.buffer = self.buffer[-keep:]
                elif not keep:
                    visible.append(self.buffer)
                    self.buffer = ""
                break

            visible.append(self.buffer[:start_idx])
            self.buffer = self.buffer[start_idx + len(THINK_START):]
            self.in_think = True

        return "".join(visible)

    def flush(self):
        if self.in_think:
            return ""
        if THINK_START in self.buffer:
            prefix = self.buffer.split(THINK_START, 1)[0]
            self.buffer = ""
            return prefix
        text = self.buffer
        self.buffer = ""
        return text


class ReasoningPreambleStripper:
    def __init__(self, placeholder=""):
        self.placeholder = placeholder
        self.buffer = ""
        self.mode = "unknown"
        self.placeholder_sent = False

    def feed(self, text):
        if self.mode == "pass":
            return text

        self.buffer += text

        if self.mode == "strip":
            return self._strip_buffer()

        if self._looks_like_reasoning(self.buffer):
            self.mode = "strip"
            output = self._emit_placeholder_once()
            output += self._strip_buffer()
            return output

        if self._can_decide_pass(self.buffer):
            self.mode = "pass"
            output = self.buffer
            self.buffer = ""
            return output

        return ""

    def flush(self):
        if self.mode == "pass":
            output = self.buffer
            self.buffer = ""
            return output

        if self.mode == "strip" or self._looks_like_reasoning(self.buffer):
            self.buffer = ""
            return self._emit_placeholder_once()

        output = self.buffer
        self.buffer = ""
        return output

    def _strip_buffer(self):
        final_match = FINAL_LABEL_RE.search(self.buffer)
        if final_match:
            self.buffer = self.buffer[final_match.end():]
            self.mode = "pass"
            output = self.buffer.lstrip()
            self.buffer = ""
            return output

        split_markers = ("\n\n", "\r\n\r\n")
        split_idx = -1
        split_len = 0
        for marker in split_markers:
            idx = self.buffer.find(marker)
            if idx != -1 and (split_idx == -1 or idx < split_idx):
                split_idx = idx
                split_len = len(marker)

        if split_idx != -1:
            tail = self.buffer[split_idx + split_len:].lstrip()
            self.buffer = ""
            if tail:
                self.mode = "pass"
                return tail
            return ""

        if len(self.buffer) > 4096:
            self.buffer = self.buffer[-256:]
        return ""

    def _emit_placeholder_once(self):
        if self.placeholder and not self.placeholder_sent:
            self.placeholder_sent = True
            return self.placeholder
        return ""

    @staticmethod
    def _looks_like_reasoning(text):
        stripped = text.lstrip()
        lowered = stripped.lower()
        if LEADING_REASONING_RE.match(stripped):
            return True
        return any(lowered.startswith(prefix) for prefix in LET_ME_THINK_PREFIXES)

    @staticmethod
    def _can_decide_pass(text):
        stripped = text.lstrip()
        if not stripped:
            return False
        if FINAL_LABEL_RE.match(stripped):
            return True
        if LEADING_REASONING_RE.match(stripped):
            return False
        lowered = stripped.lower()
        if any(lowered.startswith(prefix) for prefix in LET_ME_THINK_PREFIXES):
            return False
        return len(stripped) >= 32 or "\n" in stripped


def strip_full_text(text):
    text = THINK_BLOCK_RE.sub("", text)
    text = THINK_TAIL_RE.sub("", text)
    stripped = text.lstrip()
    if LEADING_REASONING_RE.match(stripped):
        final_match = FINAL_LABEL_RE.search(stripped)
        if final_match:
            text = stripped[final_match.end():]
        else:
            parts = re.split(r"\r?\n\r?\n", stripped, maxsplit=1)
            text = parts[1] if len(parts) == 2 else ""
    else:
        lowered = stripped.lower()
        if any(lowered.startswith(prefix) for prefix in LET_ME_THINK_PREFIXES):
            parts = re.split(r"\r?\n\r?\n", stripped, maxsplit=1)
            text = parts[1] if len(parts) == 2 else ""
    return text.strip()


def sanitize_chat_completion(payload):
    if not isinstance(payload, dict):
        return payload

    for choice in payload.get("choices", []):
        if not isinstance(choice, dict):
            continue

        message = choice.get("message")
        if isinstance(message, dict):
            message.pop("reasoning_content", None)
            message.pop("reasoning", None)
            content = message.get("content")
            if isinstance(content, str):
                message["content"] = strip_full_text(content)

        delta = choice.get("delta")
        if isinstance(delta, dict):
            delta.pop("reasoning_content", None)
            delta.pop("reasoning", None)
            content = delta.get("content")
            if isinstance(content, str):
                delta["content"] = strip_full_text(content)

    return payload


def rewrite_model_aliases(payload):
    if not isinstance(payload, dict) or not REQUEST_MODEL_ALIASES:
        return payload

    model = payload.get("model")
    if isinstance(model, str) and model in REQUEST_MODEL_ALIASES:
        payload["model"] = REQUEST_MODEL_ALIASES[model]
    if "max_tokens" in payload and "max_completion_tokens" not in payload:
        payload["max_completion_tokens"] = payload.pop("max_tokens")

    return payload


def ensure_chat_completion_metadata(payload, chunk=False):
    if not isinstance(payload, dict):
        return payload

    if not isinstance(payload.get("id"), str) or not payload.get("id"):
        payload["id"] = f"chatcmpl-{uuid.uuid4().hex[:16]}"

    if not isinstance(payload.get("created"), int):
        payload["created"] = int(time.time())

    if chunk:
        payload.setdefault("object", "chat.completion.chunk")
    else:
        payload.setdefault("object", "chat.completion")

    return payload


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.rstrip("/") == "/v1/models":
            self._send_model_list()
            return
        if self.path.rstrip("/") in {f"/v1/models/{model_id}" for model_id in MODEL_IDS}:
            self._send_model_detail()
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
        sys.stderr.write("%s - - [%s] %s\n" % (
            self.address_string(),
            self.log_date_time_string(),
            fmt % args,
        ))

    def _proxy(self):
        request_path = self.path
        upstream_url = f"{UPSTREAM_BASE}{self._upstream_path(request_path)}"
        body = self._read_body()
        if body and self._is_openai_inference_path(request_path):
            body = self._rewrite_request_payload(body)
        headers = self._forward_headers(body)

        request = Request(
            upstream_url,
            data=body,
            headers=headers,
            method=self.command,
        )

        try:
            with urlopen(request, timeout=REQUEST_TIMEOUT) as response:
                self._relay_response(response, request_path)
        except HTTPError as exc:
            self._relay_response(exc, request_path)
        except URLError as exc:
            self.send_error(502, f"Upstream connection failed: {exc.reason}")

    def _read_body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return None
        return self.rfile.read(length)

    def _forward_headers(self, body):
        headers = {}
        for key, value in self.headers.items():
            if key.lower() in HOP_BY_HOP_HEADERS or key.lower() == "host":
                continue
            if key.lower() == "content-length":
                continue
            headers[key] = value
        if body is not None:
            headers["Content-Length"] = str(len(body))
        if UPSTREAM_API_KEY:
            headers["Authorization"] = f"Bearer {UPSTREAM_API_KEY}"
        return headers

    def _send_model_list(self):
        if not MODEL_IDS:
            self.send_error(404, "No models configured")
            return

        payload = {
            "object": "list",
            "data": [
                {
                    "id": model_id,
                    "object": "model",
                    "created": int(time.time()),
                    "owned_by": "openai",
                }
                for model_id in MODEL_IDS
            ],
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_model_detail(self):
        if not MODEL_IDS:
            self.send_error(404, "No models configured")
            return

        model_id = MODEL_IDS[0]
        payload = {
            "id": model_id,
            "object": "model",
            "created": int(time.time()),
            "owned_by": "openai",
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _relay_response(self, response, request_path):
        content_type = response.headers.get("Content-Type", "")
        if self._is_streaming_chat_completion(request_path, content_type):
            self._relay_streaming_response(response)
            return

        payload = response.read()
        status = getattr(response, "status", response.getcode())

        if self._is_chat_completion(request_path) and self._is_json(content_type):
            payload = self._sanitize_json_payload(payload)

        self.send_response(status)
        for key, value in response.headers.items():
            if key.lower() in HOP_BY_HOP_HEADERS or key.lower() == "content-length":
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _relay_streaming_response(self, response):
        status = getattr(response, "status", response.getcode())
        self.send_response(status)
        for key, value in response.headers.items():
            if key.lower() in HOP_BY_HOP_HEADERS or key.lower() == "content-length":
                continue
            self.send_header(key, value)
        self.end_headers()

        strip_state = {}
        preamble_state = {}
        while True:
            line = response.readline()
            if not line:
                break

            if not line.startswith(b"data: "):
                self.wfile.write(line)
                self.wfile.flush()
                continue

            data = line[6:].strip()
            if not data:
                self.wfile.write(line)
                self.wfile.flush()
                continue
            if data == b"[DONE]":
                self._flush_stream_state(strip_state, preamble_state)
                self.wfile.write(line)
                self.wfile.flush()
                continue

            try:
                event = json.loads(data)
            except json.JSONDecodeError:
                self.wfile.write(line)
                self.wfile.flush()
                continue

            changed = False
            kept_choices = []
            for choice in event.get("choices", []):
                if not isinstance(choice, dict):
                    continue
                delta = choice.get("delta")
                if not isinstance(delta, dict):
                    kept_choices.append(choice)
                    continue

                delta.pop("reasoning_content", None)
                delta.pop("reasoning", None)
                changed = True
                content = delta.get("content")
                if isinstance(content, str):
                    idx = choice.get("index", 0)
                    stripper = strip_state.setdefault(idx, ThinkStripper())
                    preamble = preamble_state.setdefault(
                        idx, ReasoningPreambleStripper(THINKING_PLACEHOLDER)
                    )
                    cleaned = stripper.feed(content)
                    cleaned = preamble.feed(cleaned)
                    if cleaned:
                        delta["content"] = cleaned
                        kept_choices.append(choice)
                    else:
                        delta.pop("content", None)
                elif delta:
                    kept_choices.append(choice)
                elif choice.get("finish_reason") is not None:
                    kept_choices.append(choice)

            if changed:
                event["choices"] = kept_choices
                if not kept_choices:
                    continue

            event = ensure_chat_completion_metadata(event, chunk=True)
            output = json.dumps(event, ensure_ascii=False).encode("utf-8")
            self.wfile.write(b"data: " + output + b"\n\n")
            self.wfile.flush()

    def _flush_stream_state(self, strip_state, preamble_state):
        events = []
        for idx in sorted(set(strip_state) | set(preamble_state)):
            content = ""
            if idx in strip_state:
                content += strip_state[idx].flush()
            if idx in preamble_state:
                content = preamble_state[idx].feed(content) + preamble_state[idx].flush()
            if not content:
                continue
            events.append({
                "id": f"chatcmpl-{uuid.uuid4().hex[:16]}",
                "created": int(time.time()),
                "object": "chat.completion.chunk",
                "choices": [{
                    "index": idx,
                    "delta": {"content": content},
                }],
            })

        for event in events:
            output = json.dumps(event, ensure_ascii=False).encode("utf-8")
            self.wfile.write(b"data: " + output + b"\n\n")
            self.wfile.flush()

    def _sanitize_json_payload(self, payload):
        try:
            data = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return payload
        sanitized = sanitize_chat_completion(data)
        sanitized = ensure_chat_completion_metadata(sanitized)
        return json.dumps(sanitized, ensure_ascii=False).encode("utf-8")

    def _rewrite_request_payload(self, body):
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return body

        payload = rewrite_model_aliases(payload)
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    @staticmethod
    def _is_json(content_type):
        return "application/json" in content_type

    @staticmethod
    def _is_chat_completion(path):
        return path.endswith("/v1/chat/completions")

    @classmethod
    def _is_streaming_chat_completion(cls, path, content_type):
        return cls._is_chat_completion(path) and "text/event-stream" in content_type

    @staticmethod
    def _is_openai_inference_path(path):
        return path.endswith("/v1/chat/completions") or path.endswith("/v1/completions")

    def _upstream_path(self, request_path):
        if UPSTREAM_BASE.rstrip("/").endswith("/v1") and self.path.startswith("/v1/"):
            return request_path[3:]
        return request_path


def main():
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), ProxyHandler)

    def shutdown(*_args):
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    print(
        f"Reasoning proxy listening on http://{LISTEN_HOST}:{LISTEN_PORT} -> {UPSTREAM_BASE}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
