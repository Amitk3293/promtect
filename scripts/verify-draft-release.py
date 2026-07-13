#!/usr/bin/env python3
"""Validate that a GitHub draft release still belongs to the reviewed source."""

import argparse
import json
import sys


def fail(message: str) -> None:
    raise SystemExit(f"draft release verification error: {message}")


parser = argparse.ArgumentParser()
parser.add_argument("tag")
parser.add_argument("source_sha")
parser.add_argument("--assets", action="store_true")
args = parser.parse_args()

try:
    data = json.load(sys.stdin)
except (json.JSONDecodeError, UnicodeDecodeError) as error:
    fail(f"invalid GitHub response: {error}")
if not isinstance(data, dict):
    fail("GitHub response is not an object")
if data.get("tagName") != args.tag:
    fail("tag does not match validated tag")
if data.get("isDraft") is not True:
    fail("release is not an unpublished draft")
if data.get("targetCommitish") != args.source_sha:
    fail("target does not match validated source SHA")

if args.assets:
    targets = (
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "aarch64-unknown-linux-gnu",
        "x86_64-unknown-linux-gnu",
    )
    expected = {
        name
        for target in targets
        for name in (
            f"promtect-{args.tag}-{target}.tar.gz",
            f"promtect-{args.tag}-{target}.tar.gz.sha256",
        )
    }
    assets = data.get("assets")
    if not isinstance(assets, list) or not all(
        isinstance(asset, dict) and isinstance(asset.get("name"), str)
        for asset in assets
    ):
        fail("asset response is invalid")
    actual = [asset["name"] for asset in assets]
    if len(actual) != len(set(actual)) or set(actual) != expected:
        fail("draft has an incomplete or unexpected asset set")

print(f"draft release verified: {args.tag}, {args.source_sha}")
