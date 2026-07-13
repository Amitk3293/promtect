#!/usr/bin/env python3
"""Refuse immutable GHCR tag replacement and rolling-minor regression."""

import json
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(f"GHCR tag verification error: {message}")


if len(sys.argv) != 3:
    fail("usage: check-ghcr-tags.py vX.Y.Z versions.json")

tag, versions_path = sys.argv[1:]
match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", tag)
if match is None:
    fail("tag must be a stable vX.Y.Z tag")
major, minor, patch = (int(part) for part in match.groups())
version = f"{major}.{minor}.{patch}"
rolling = f"{major}.{minor}"

with open(versions_path, encoding="utf-8") as handle:
    pages = json.load(handle)
if not isinstance(pages, list):
    fail("package versions response is not a list")
if pages and all(isinstance(page, list) for page in pages):
    records = [record for page in pages for record in page]
else:
    records = pages

tags: set[str] = set()
for record in records:
    if not isinstance(record, dict):
        fail("package versions response contains a non-object record")
    metadata = record.get("metadata", {})
    container = metadata.get("container", {}) if isinstance(metadata, dict) else {}
    record_tags = container.get("tags", []) if isinstance(container, dict) else []
    if not isinstance(record_tags, list) or not all(
        isinstance(item, str) for item in record_tags
    ):
        fail("package version contains an invalid tag list")
    tags.update(record_tags)

for immutable in (version, tag):
    if immutable in tags:
        fail(f"immutable version tag already exists: {immutable}")

same_line_patches: list[int] = []
for existing in tags:
    existing_match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", existing)
    if existing_match is None:
        continue
    existing_major, existing_minor, existing_patch = (
        int(part) for part in existing_match.groups()
    )
    if (existing_major, existing_minor) == (major, minor):
        same_line_patches.append(existing_patch)

if same_line_patches and max(same_line_patches) >= patch:
    fail(
        f"{rolling} would regress from patch {max(same_line_patches)} to {patch}"
    )
if rolling in tags and not same_line_patches:
    fail(f"cannot prove current {rolling} provenance from immutable version tags")

print(f"GHCR tags safe to create: {version}, {tag}; {rolling} advances monotonically")
