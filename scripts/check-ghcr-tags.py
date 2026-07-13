#!/usr/bin/env python3
"""Verify grouped GHCR tag provenance before or after publication."""

import argparse
import json
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"GHCR tag verification error: {message}")


parser = argparse.ArgumentParser()
parser.add_argument("tag")
parser.add_argument("versions_path")
parser.add_argument("--expected-digest")
parser.add_argument("--state-output", type=Path)
args = parser.parse_args()

tag = args.tag
match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", tag)
if match is None:
    fail("tag must be a stable vX.Y.Z tag")
major, minor, patch = (int(part) for part in match.groups())
version = f"{major}.{minor}.{patch}"
rolling = f"{major}.{minor}"

with open(args.versions_path, encoding="utf-8") as handle:
    pages = json.load(handle)
if not isinstance(pages, list):
    fail("package versions response is not a list")
if pages and all(isinstance(page, list) for page in pages):
    records = [record for page in pages for record in page]
else:
    records = pages

records_by_digest: dict[str, set[str]] = {}
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
    digest = record.get("name")
    if not isinstance(digest, str) or not digest:
        fail("package version contains no digest name")
    normalized_digest = digest.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", normalized_digest):
        fail("package version digest name is invalid")
    if normalized_digest in records_by_digest:
        fail("package versions response contains a duplicate digest record")
    records_by_digest[normalized_digest] = set(record_tags)

all_tags = {item for record_tags in records_by_digest.values() for item in record_tags}
owners_by_tag: dict[str, list[str]] = {}
for digest, record_tags in records_by_digest.items():
    for record_tag in record_tags:
        owners_by_tag.setdefault(record_tag, []).append(digest)
for record_tag, owners in owners_by_tag.items():
    if len(owners) != 1:
        fail(f"tag has multiple digest owners: {record_tag}")

expected_digest = args.expected_digest
if expected_digest is not None:
    if args.state_output is not None:
        fail("state output is only available during pre-publication verification")
    normalized_expected = expected_digest.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", normalized_expected):
        fail("expected pushed digest is invalid")
    pushed_tags = records_by_digest.get(normalized_expected)
    if pushed_tags is None:
        fail("pushed digest is absent from the package versions response")
    required = {version, tag, rolling}
    if not required.issubset(pushed_tags):
        fail("pushed digest does not own all exact and rolling tags")
    for required_tag in required:
        owners = [
            digest
            for digest, record_tags in records_by_digest.items()
            if required_tag in record_tags
        ]
        if owners != [normalized_expected]:
            fail(f"published tag has conflicting digest ownership: {required_tag}")
    print(f"GHCR push verified: {version}, {tag}, {rolling} -> sha256:{normalized_expected}")
    raise SystemExit(0)

for immutable in (version, tag):
    if immutable in all_tags:
        fail(f"immutable version tag already exists: {immutable}")

if "latest" in all_tags:
    fail("deprecated latest tag still exists; remove it before publishing")

same_line_patches: set[int] = set()
for record_tags in records_by_digest.values():
    unprefixed: set[int] = set()
    prefixed: set[int] = set()
    for existing in record_tags:
        existing_match = re.fullmatch(r"(v?)(\d+)\.(\d+)\.(\d+)", existing)
        if existing_match is None:
            continue
        prefix, existing_major, existing_minor, existing_patch = existing_match.groups()
        if (int(existing_major), int(existing_minor)) != (major, minor):
            continue
        (prefixed if prefix else unprefixed).add(int(existing_patch))
    if unprefixed != prefixed:
        fail("immutable same-line tags are not paired on one digest record")
    same_line_patches.update(unprefixed)

if same_line_patches and max(same_line_patches) >= patch:
    fail(
        f"{rolling} would regress from patch {max(same_line_patches)} to {patch}"
    )
rolling_owners = [
    (digest, record_tags)
    for digest, record_tags in records_by_digest.items()
    if rolling in record_tags
]
if len(rolling_owners) > 1:
    fail(f"{rolling} has multiple digest owners")
if rolling_owners:
    rolling_digest, rolling_tags = rolling_owners[0]
    rolling_patches = {
        int(existing_match.group(1))
        for existing in rolling_tags
        if (existing_match := re.fullmatch(rf"(?:v)?{major}\.{minor}\.(\d+)", existing))
    }
    if len(rolling_patches) != 1:
        fail(f"cannot prove current {rolling} provenance from one immutable tag pair")
    rolling_patch = next(iter(rolling_patches))
    if not {f"{rolling}.{rolling_patch}", f"v{rolling}.{rolling_patch}"}.issubset(
        rolling_tags
    ):
        fail(f"current {rolling} digest does not own its immutable tag pair")
    if same_line_patches and rolling_patch != max(same_line_patches):
        fail(f"{rolling} does not point to the highest immutable same-line patch")
else:
    rolling_digest = None

if args.state_output is not None:
    args.state_output.write_text(
        json.dumps(
            {
                "rolling": rolling,
                "rolling_digest": (
                    f"sha256:{rolling_digest}" if rolling_digest is not None else None
                ),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

print(f"GHCR tags safe to create: {version}, {tag}; {rolling} advances monotonically")
