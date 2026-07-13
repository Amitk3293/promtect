#!/usr/bin/env python3
"""Verify that every real CLI reached only the sanitized internal observer."""

import json
import urllib.request

EXPECTED_PROMPT_PATHS = {
    "/v1/messages",
    "/v1/responses",
    "/v1/chat/completions",
}
OLLAMA_PROMPT_PATHS = {"/api/chat", "/api/generate"}

with urllib.request.urlopen("http://mock-provider:9000/__observations", timeout=5) as response:
    observations = json.load(response)

cli = [item for item in observations if item.get("source") == "real-cli"]
paths = {item["path"] for item in cli if item.get("sentinel_seen")}
missing = EXPECTED_PROMPT_PATHS - paths
assert not missing, f"real CLI requests missing from observer: {sorted(missing)}"
assert paths & OLLAMA_PROMPT_PATHS, "Ollama prompt request missing from observer"
assert all(not item["plaintext_canary_seen"] for item in cli), "plaintext canary reached mock"
assert all("body" not in item for item in cli), "raw real-CLI body was retained"
print("PASS CLI safety: all four CLIs reached the internal observer masked; raw bodies were not retained")
