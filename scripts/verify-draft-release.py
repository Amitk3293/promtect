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
parser.add_argument("--assets-subset", action="store_true")
parser.add_argument("--normalization-candidate", action="store_true")
args = parser.parse_args()

if sum((args.assets, args.assets_subset, args.normalization_candidate)) > 1:
    fail("choose only one asset validation mode")

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
if not args.normalization_candidate:
    if data.get("isPrerelease") is not False:
        fail("release is marked as a prerelease")
    expected_name = f"Promtect {args.tag}"
    if data.get("name") != expected_name:
        fail("release title does not match deterministic title")
    expected_body = (
        f"<!-- promtect-core-release:v1 tag={args.tag} source={args.source_sha} -->\n\n"
        f"Promtect Core {args.tag}.\n\n"
        "Verify the attached archives with their SHA-256 sidecars before installation."
    )
    if data.get("body") != expected_body:
        fail("release body does not match deterministic reviewed metadata")

if args.assets or args.assets_subset or args.normalization_candidate:
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
    if len(actual) != len(set(actual)):
        fail("draft has duplicate assets")
    if args.assets and set(actual) != expected:
        fail("draft has an incomplete or unexpected asset set")
    if (args.assets_subset or args.normalization_candidate) and not set(
        actual
    ).issubset(expected):
        fail("draft has an unexpected asset")

print(f"draft release verified: {args.tag}, {args.source_sha}")
