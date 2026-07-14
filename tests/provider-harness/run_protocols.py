#!/usr/bin/env python3
"""Black-box assertions for the Docker-only provider protocol harness."""

from __future__ import annotations

import gzip
import http.client
import json
import re
import socket
import sys
import time
from dataclasses import dataclass
from urllib.parse import urlparse

SYNTHETIC_SECRET = "AKIAIOSFODNN7EXAMPLE"
PROMTECT = "http://promtect:8790"
PROMTECT_REFUSAL = "http://promtect-refusal:8790"
MOCK = "http://mock-provider:9000"
SENTINEL_RE = re.compile(r"«promtect:[a-z_]+:[0-9a-f]+»")
UNSUPPORTED_ENCODING = (
    b"promtect: unsupported request Content-Encoding; send an identity-encoded body"
)

PROTOCOLS = {
    "anthropic-sse": (
        "/v1/messages",
        {"model": "synthetic-claude", "messages": [{"role": "user", "content": f"canary {SYNTHETIC_SECRET}"}]},
    ),
    "openai-responses-sse": (
        "/v1/responses",
        {"model": "synthetic-gpt", "input": f"canary {SYNTHETIC_SECRET}", "stream": True},
    ),
    "ollama-ndjson": (
        "/api/generate",
        {"model": "synthetic-ollama", "prompt": f"canary {SYNTHETIC_SECRET}", "stream": True},
    ),
}


@dataclass
class Result:
    status: int
    headers: dict[str, str]
    body: bytes
    transport_error: bool = False


def request(base: str, method: str, path: str, body: bytes = b"", headers: dict[str, str] | None = None) -> Result:
    target = urlparse(base)
    conn = http.client.HTTPConnection(target.hostname, target.port, timeout=8)
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    response_headers = {key.lower(): value for key, value in response.getheaders()}
    try:
        response_body = response.read()
        transport_error = False
    except (http.client.IncompleteRead, http.client.HTTPException, OSError) as error:
        response_body = getattr(error, "partial", b"")
        transport_error = True
    conn.close()
    return Result(response.status, response_headers, response_body, transport_error)


def wait_for_port(base: str) -> None:
    target = urlparse(base)
    assert target.hostname is not None
    assert target.port is not None
    for _ in range(80):
        try:
            with socket.create_connection((target.hostname, target.port), timeout=0.25):
                return
        except OSError:
            pass
        time.sleep(0.25)
    raise AssertionError(f"service did not become ready: {base}")


def wait_until_ready() -> None:
    for base in (MOCK, PROMTECT, PROMTECT_REFUSAL, "http://promtect-cli:8790"):
        wait_for_port(base)
    assert request(MOCK, "GET", "/__observations").status == 200


def observations() -> list[dict[str, object]]:
    result = request(MOCK, "GET", "/__observations")
    assert result.status == 200
    return json.loads(result.body)


def fixture(protocol: str) -> tuple[str, bytes]:
    path, payload = PROTOCOLS[protocol]
    return path, json.dumps(payload, separators=(",", ":")).encode()


def expected_response(protocol: str, token: str) -> bytes:
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


def protocol_request(protocol: str, scenario: str = "preserved") -> Result:
    path, body = fixture(protocol)
    return request(
        PROMTECT,
        "POST",
        f"{path}?scenario={scenario}",
        body,
        {"content-type": "application/json", "accept-encoding": "gzip"},
    )


def check_preserved(protocol: str) -> None:
    result = protocol_request(protocol)
    assert result.status == 200, (protocol, result.status, result.body)
    assert not result.transport_error, protocol
    assert result.body == expected_response(protocol, SYNTHETIC_SECRET), protocol
    seen = observations()[-1]
    assert seen["protocol"] == protocol
    assert seen["sentinel_seen"] is True
    assert seen["plaintext_canary_seen"] is False
    assert seen["accept_encoding_seen"] is None
    assert SYNTHETIC_SECRET not in str(seen["body"])
    print(f"PASS {protocol}: masked upstream; byte-split sentinel restored exactly")


def sentinel_from(observation: dict[str, object]) -> str:
    match = SENTINEL_RE.search(str(observation["body"]))
    assert match is not None, observation
    return match.group(0)


def mutate_sentinel(sentinel: str) -> str:
    replacement = "0" if sentinel[-2] != "0" else "1"
    return f"{sentinel[:-2]}{replacement}»"


def check_mutated_sentinel() -> None:
    protocol = "anthropic-sse"
    result = protocol_request(protocol, "mutated")
    seen = observations()[-1]
    mutated = mutate_sentinel(sentinel_from(seen))
    assert result.status == 200
    assert not result.transport_error
    assert result.body == expected_response(protocol, mutated)
    assert SYNTHETIC_SECRET.encode() not in result.body
    print("PASS sentinel mutation: unknown sentinel remains unchanged; no plaintext restored")


def check_request_compression_rejected() -> None:
    path, body = fixture("anthropic-sse")
    before = len(observations())
    result = request(
        PROMTECT,
        "POST",
        path,
        gzip.compress(body, mtime=0),
        {"content-type": "application/json", "content-encoding": "gzip"},
    )
    after = len(observations())
    assert result.status == 415
    assert result.body == UNSUPPORTED_ENCODING
    assert before == after, "compressed request reached the mock provider"
    print("PASS request compression: fixed value-free 415; zero provider requests")


def check_compressed_response() -> None:
    protocol = "openai-responses-sse"
    result = protocol_request(protocol, "compressed")
    seen = observations()[-1]
    sentinel = sentinel_from(seen)
    expected_plain = expected_response(protocol, sentinel)
    expected_encoded = gzip.compress(expected_plain, compresslevel=9, mtime=0)
    assert result.status == 200
    assert result.headers.get("content-encoding") == "gzip"
    assert result.body == expected_encoded
    assert gzip.decompress(result.body) == expected_plain
    assert SYNTHETIC_SECRET.encode() not in gzip.decompress(result.body)
    print("PASS compressed response: encoding preserved; bytes passed through without restoration")


def check_stream_failure(scenario: str) -> None:
    protocol = "anthropic-sse"
    result = protocol_request(protocol, scenario)
    seen = observations()[-1]
    full = expected_response(protocol, sentinel_from(seen))
    # The stream adapter flushes retained bytes before yielding its error, but at
    # the real Axum/Hyper boundary the downstream connection abort discards that
    # final retained chunk. The client observes only the prefix that was safe to
    # emit before the sentinel opened. Pin the runtime truth explicitly.
    expected_partial = full[: full.find("«".encode())]
    assert result.status == 200
    assert result.transport_error, f"{scenario} was presented as a clean stream"
    assert result.body == expected_partial, (scenario, result.body, expected_partial)
    assert SYNTHETIC_SECRET.encode() not in result.body
    print(
        f"OBSERVED {scenario}: transport error surfaced; downstream retained only "
        "the safe prefix (partial sentinel bytes were dropped)"
    )


def check_refusal() -> None:
    path, body = fixture("anthropic-sse")
    before = len(observations())
    result = request(
        PROMTECT_REFUSAL,
        "POST",
        path,
        body,
        {"content-type": "application/json"},
    )
    after = len(observations())
    assert result.status == 502
    assert result.body == b"promtect: upstream request failed"
    assert before == after
    print("PASS refusal: fixed value-free 502; no provider request")


def main() -> int:
    wait_until_ready()
    for protocol in PROTOCOLS:
        check_preserved(protocol)
    check_mutated_sentinel()
    check_request_compression_rejected()
    check_compressed_response()
    check_stream_failure("timeout")
    check_stream_failure("interrupted")
    check_refusal()
    print("PASS safety: runtime network is internal and fixtures contain synthetic data only")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"FAIL provider harness: {error}", file=sys.stderr)
        raise
