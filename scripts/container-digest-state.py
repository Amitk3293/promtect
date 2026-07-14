#!/usr/bin/env python3
"""Create and verify restart-safe GHCR publication digest records."""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"container digest state error: {message}")


def valid_tag(value: str) -> bool:
    return re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", value) is not None


def normalize_digest(value: str) -> str:
    normalized = value.removeprefix("sha256:")
    if re.fullmatch(r"[0-9a-f]{64}", normalized) is None:
        fail("digest is invalid")
    return f"sha256:{normalized}"


def valid_source_sha(value: str) -> bool:
    return re.fullmatch(r"[0-9a-f]{40}", value) is not None


def load_object(path: Path, description: str) -> dict[str, Any]:
    value = load_json(path, description)
    if not isinstance(value, dict):
        fail(f"{description} is not an object")
    return value


def load_json(path: Path, description: str) -> Any:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"could not read {description}: {error}")
    return value


def create_record(path: Path, tag: str, source_sha: str, digest: str) -> None:
    if not valid_tag(tag):
        fail("tag must be a stable vX.Y.Z tag")
    if not valid_source_sha(source_sha):
        fail("source SHA is invalid")
    record = {
        "schema_version": 1,
        "product": "promtect-core-container",
        "tag": tag,
        "source_sha": source_sha,
        "digest": normalize_digest(digest),
    }
    path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")


def verify_record(path: Path, tag: str, source_sha: str) -> None:
    record = load_object(path, "digest record")
    expected_keys = {"schema_version", "product", "tag", "source_sha", "digest"}
    if set(record) != expected_keys:
        fail("digest record fields are not exact")
    if record.get("schema_version") != 1:
        fail("digest record schema version is unsupported")
    if record.get("product") != "promtect-core-container":
        fail("digest record product is invalid")
    if not valid_tag(tag) or record.get("tag") != tag:
        fail("digest record tag does not match")
    if not valid_source_sha(source_sha) or record.get("source_sha") != source_sha:
        fail("digest record source SHA does not match")
    digest = record.get("digest")
    if not isinstance(digest, str):
        fail("digest record digest is invalid")
    print(normalize_digest(digest))


def select_artifact(path: Path, name: str, source_sha: str) -> None:
    response = load_json(path, "artifact response")
    pages = response if isinstance(response, list) else [response]
    artifacts: list[Any] = []
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get("artifacts"), list):
            fail("artifact response has no artifact list")
        artifacts.extend(page["artifacts"])
    if not name or not valid_source_sha(source_sha):
        fail("artifact selection inputs are invalid")

    candidates: list[tuple[datetime, int]] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict) or artifact.get("name") != name:
            continue
        workflow_run = artifact.get("workflow_run")
        if not isinstance(workflow_run, dict):
            fail("matching artifact has no workflow-run binding")
        if workflow_run.get("head_sha") != source_sha:
            continue
        if workflow_run.get("head_branch") != "main":
            continue
        if artifact.get("expired") is not False:
            continue
        identifier = artifact.get("id")
        created_at = artifact.get("created_at")
        if not isinstance(identifier, int) or not isinstance(created_at, str):
            fail("matching artifact metadata is invalid")
        try:
            timestamp = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except ValueError:
            fail("matching artifact timestamp is invalid")
        candidates.append((timestamp, identifier))

    if candidates:
        print(min(candidates)[1])


parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="command", required=True)

create = subparsers.add_parser("create")
create.add_argument("path", type=Path)
create.add_argument("tag")
create.add_argument("source_sha")
create.add_argument("digest")

verify = subparsers.add_parser("verify")
verify.add_argument("path", type=Path)
verify.add_argument("tag")
verify.add_argument("source_sha")

select = subparsers.add_parser("select-artifact")
select.add_argument("path", type=Path)
select.add_argument("name")
select.add_argument("source_sha")

args = parser.parse_args()
if args.command == "create":
    create_record(args.path, args.tag, args.source_sha, args.digest)
elif args.command == "verify":
    verify_record(args.path, args.tag, args.source_sha)
else:
    select_artifact(args.path, args.name, args.source_sha)
