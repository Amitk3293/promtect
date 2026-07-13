#!/usr/bin/env python3
"""Credential-free mock for Promtect's supported provider wire protocols."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.parse import parse_qs, urlparse

SYNTHETIC_SECRET = "AKIAIOSFODNN7EXAMPLE"
SENTINEL_RE = re.compile(r"«promtect:[a-z_]+:[0-9a-f]+»")
PROMPT_PATHS = {
    "/v1/messages",
    "/v1/responses",
    "/v1/chat/completions",
    "/api/generate",
    "/api/chat",
}
METADATA_PATHS = {"/api/show", "/api/version", "/api/tags"}

observations: list[dict[str, object]] = []
observations_lock = Lock()


def protocol_for(path: str) -> str:
    return {
        "/v1/messages": "anthropic-sse",
        "/v1/responses": "openai-responses-sse",
        "/v1/chat/completions": "openai-chat-sse",
        "/api/generate": "ollama-ndjson",
        "/api/chat": "ollama-chat-ndjson",
    }[path]


def response_body(protocol: str, token: str) -> bytes:
    if protocol == "anthropic-sse":
        return (
            "event: content_block_delta\n"
            'data: {"type":"content_block_delta","delta":{"type":"text_delta",'
            f'"text":"masked:{token}"}}}}\n\n'
            "event: message_stop\n"
            'data: {"type":"message_stop"}\n\n'
        ).encode()
    if protocol == "openai-responses-sse":
        return (
            "event: response.output_text.delta\n"
            f'data: {{"type":"response.output_text.delta","delta":"masked:{token}"}}\n\n'
            "event: response.completed\n"
            'data: {"type":"response.completed"}\n\n'
        ).encode()
    if protocol == "openai-chat-sse":
        chunk = json.dumps(
            {
                "id": "chatcmpl-synthetic",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": "synthetic-model",
                "choices": [
                    {
                        "index": 0,
                        "delta": {"role": "assistant", "content": f"masked:{token}"},
                        "finish_reason": None,
                    }
                ],
            },
            separators=(",", ":"),
            ensure_ascii=False,
        )
        done = json.dumps(
            {
                "id": "chatcmpl-synthetic",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": "synthetic-model",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            },
            separators=(",", ":"),
        )
        return f"data: {chunk}\n\ndata: {done}\n\ndata: [DONE]\n\n".encode()
    if protocol == "ollama-chat-ndjson":
        return (
            json.dumps(
                {
                    "model": "synthetic-model",
                    "message": {"role": "assistant", "content": f"masked:{token}"},
                    "done": True,
                    "done_reason": "stop",
                    "prompt_eval_count": 1,
                    "eval_count": 1,
                },
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
        ).encode()
    first = json.dumps(
        {"model": "synthetic", "response": f"masked:{token}", "done": False},
        separators=(",", ":"),
        ensure_ascii=False,
    )
    second = json.dumps(
        {"model": "synthetic", "done": True},
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return f"{first}\n{second}\n".encode()


def mutate_sentinel(sentinel: str) -> str:
    replacement = "0" if sentinel[-2] != "0" else "1"
    return f"{sentinel[:-2]}{replacement}»"


def cli_response_body(protocol: str, token: str) -> bytes:
    if protocol == "openai-responses-sse":
        events = [
            {
                "type": "response.created",
                "response": {"id": "resp_synthetic"},
            },
            {
                "type": "response.output_item.done",
                "item": {
                    "type": "message",
                    "role": "assistant",
                    "id": "msg_synthetic",
                    "content": [{"type": "output_text", "text": f"masked:{token}"}],
                },
            },
            {
                "type": "response.completed",
                "response": {
                    "id": "resp_synthetic",
                    "usage": {
                        "input_tokens": 1,
                        "input_tokens_details": None,
                        "output_tokens": 1,
                        "output_tokens_details": None,
                        "total_tokens": 2,
                    },
                },
            },
        ]
        return "".join(
            f"data: {json.dumps(event, separators=(',', ':'), ensure_ascii=False)}\n\n"
            for event in events
        ).encode()
    if protocol == "anthropic-sse":
        events = [
            (
                "message_start",
                {
                    "type": "message_start",
                    "message": {
                        "id": "msg_synthetic",
                        "type": "message",
                        "role": "assistant",
                        "model": "synthetic-model",
                        "content": [],
                        "stop_reason": None,
                        "stop_sequence": None,
                        "usage": {"input_tokens": 1, "output_tokens": 0},
                    },
                },
            ),
            (
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                },
            ),
            (
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": f"masked:{token}"},
                },
            ),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            (
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": 1},
                },
            ),
            ("message_stop", {"type": "message_stop"}),
        ]
        return "".join(
            f"event: {name}\ndata: {json.dumps(event, separators=(',', ':'), ensure_ascii=False)}\n\n"
            for name, event in events
        ).encode()
    return response_body(protocol, token)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_HEAD(self) -> None:
        path = urlparse(self.path).path
        if path in {"/", "/cli/"}:
            with observations_lock:
                observations.append(
                    {
                        "source": "real-cli" if path.startswith("/cli/") else "unknown",
                        "path": "/",
                        "method": "HEAD",
                        "metadata_only": True,
                        "plaintext_canary_seen": False,
                        "sentinel_seen": False,
                    }
                )
            self.send_response(200)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        self.send_error(404)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/cli/") and path.removeprefix("/cli") in METADATA_PATHS:
            self._record_metadata("GET", path.removeprefix("/cli"))
            self._metadata_response(path.removeprefix("/cli"))
            return
        if path != "/__observations":
            with observations_lock:
                observations.append(
                    {
                        "source": "real-cli" if path.startswith("/cli/") else "unknown",
                        "path": path.removeprefix("/cli"),
                        "method": "GET",
                        "unexpected": True,
                        "plaintext_canary_seen": False,
                        "sentinel_seen": False,
                    }
                )
            self.send_error(404)
            return
        with observations_lock:
            payload = json.dumps(observations, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/cli/"):
            source = "real-cli"
            logical_path = parsed.path.removeprefix("/cli")
        elif parsed.path.startswith("/guard-cli/"):
            source = "guard-codex"
            logical_path = parsed.path.removeprefix("/guard-cli")
        elif parsed.path.startswith("/codex-base-url-control/"):
            source = "codex-base-url-control"
            logical_path = parsed.path.removeprefix("/codex-base-url-control")
        else:
            source = "protocol-fixture"
            logical_path = parsed.path
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        text = raw.decode("utf-8", errors="replace")
        sentinel_match = SENTINEL_RE.search(text)
        leaked = SYNTHETIC_SECRET.encode() in raw

        if logical_path not in PROMPT_PATHS | METADATA_PATHS:
            with observations_lock:
                observations.append(
                    {
                        "source": source,
                        "path": logical_path,
                        "method": "POST",
                        "unexpected": True,
                        "body_sha256": hashlib.sha256(raw).hexdigest(),
                        "body_bytes": len(raw),
                        "plaintext_canary_seen": leaked,
                        "sentinel_seen": sentinel_match is not None,
                    }
                )
            if leaked:
                self._unsafe_request()
            else:
                self.send_error(404)
            return

        if logical_path in METADATA_PATHS:
            self._record_metadata(
                "POST",
                logical_path,
                raw=raw,
                leaked=leaked,
                sentinel_seen=sentinel_match is not None,
            )
            if leaked:
                self._unsafe_request()
                return
            self._metadata_response(logical_path)
            return
        protocol = protocol_for(logical_path)
        scenario = parse_qs(parsed.query).get("scenario", ["preserved"])[0]
        observation = {
            "source": source,
            "path": logical_path,
            "protocol": protocol,
            "scenario": scenario,
            "body_sha256": hashlib.sha256(raw).hexdigest(),
            "body_bytes": len(raw),
            "accept_encoding_seen": self.headers.get("accept-encoding"),
            "content_encoding_seen": self.headers.get("content-encoding"),
            "plaintext_canary_seen": leaked,
            "sentinel_seen": sentinel_match is not None,
        }
        if source == "protocol-fixture":
            # Protocol fixtures are exact synthetic JSON and are returned as
            # sanitized evidence. Real CLI bodies can contain built-in system
            # prompts, so the observer deliberately retains metadata only.
            observation["body"] = text
        with observations_lock:
            observations.append(observation)

        # The mock is a safety tripwire as well as an observer. A leaked canary or
        # an unmasked fixture never receives a successful provider-shaped reply.
        if leaked or sentinel_match is None:
            self._unsafe_request()
            return

        sentinel = sentinel_match.group(0)
        token = mutate_sentinel(sentinel) if scenario == "mutated" else sentinel
        body = cli_response_body(protocol, token) if source != "protocol-fixture" else response_body(protocol, token)
        content_type = (
            "application/x-ndjson"
            if protocol in {"ollama-ndjson", "ollama-chat-ndjson"}
            else "text/event-stream"
        )

        if scenario == "compressed":
            encoded = gzip.compress(body, compresslevel=9, mtime=0)
            self.send_response(200)
            self.send_header("content-type", content_type)
            self.send_header("content-encoding", "gzip")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return

        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()

        if scenario in {"timeout", "interrupted"}:
            cut = body.find("«".encode()) + len("«promtect:".encode())
            partial = body[:cut]
            self._write_chunk(partial)
            self.wfile.flush()
            if scenario == "timeout":
                time.sleep(2.5)
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return

        # One-byte chunks force the proxy's stream restorer across every UTF-8
        # and sentinel boundary, including the two-byte guillemets.
        for byte in body:
            self._write_chunk(bytes([byte]))
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _write_chunk(self, chunk: bytes) -> None:
        self.wfile.write(f"{len(chunk):x}\r\n".encode())
        self.wfile.write(chunk)
        self.wfile.write(b"\r\n")

    def _metadata_response(self, path: str) -> None:
        if path == "/api/version":
            payload = {"version": "0.31.2"}
        elif path == "/api/tags":
            payload = {"models": [{"name": "synthetic-model:latest", "model": "synthetic-model:latest"}]}
        else:
            payload = {
                "modelfile": "FROM synthetic-model",
                "parameters": "",
                "template": "{{ .Prompt }}",
                "details": {
                    "parent_model": "",
                    "format": "gguf",
                    "family": "synthetic",
                    "families": ["synthetic"],
                    "parameter_size": "1B",
                    "quantization_level": "Q4_0",
                },
                "model_info": {},
                "capabilities": ["completion"],
            }
        encoded = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _unsafe_request(self) -> None:
        payload = b'{"error":"unsafe harness request rejected"}'
        self.send_response(422)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _record_metadata(
        self,
        method: str,
        path: str,
        *,
        raw: bytes = b"",
        leaked: bool = False,
        sentinel_seen: bool = False,
    ) -> None:
        with observations_lock:
            observations.append(
                {
                    "source": "real-cli",
                    "path": path,
                    "method": method,
                    "metadata_only": True,
                    "body_sha256": hashlib.sha256(raw).hexdigest(),
                    "body_bytes": len(raw),
                    "plaintext_canary_seen": leaked,
                    "sentinel_seen": sentinel_seen,
                }
            )


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
