#!/usr/bin/env python3
"""Build one hash lock from the exact wheels selected for both target platforms."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path


TARGETS = ("linux-amd64", "linux-arm64")


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def read_wheels(directory: Path) -> dict[str, tuple[str, set[str]]]:
    packages: dict[str, tuple[str, set[str]]] = {}
    for wheel in sorted(directory.glob("*.whl")):
        parts = wheel.name.split("-")
        if len(parts) < 5:
            raise SystemExit(f"invalid wheel filename: {wheel.name}")
        name, version = normalize(parts[0]), parts[1]
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        existing_version, hashes = packages.get(name, (version, set()))
        if existing_version != version:
            raise SystemExit(
                f"multiple versions for {name}: {existing_version} and {version}"
            )
        hashes.add(digest)
        packages[name] = (version, hashes)
    if not packages:
        raise SystemExit(f"no wheels found in {directory}")
    return packages


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: generate_requirements_lock.py <amd64-dir> <arm64-dir> <output>"
        )

    target_packages = {
        target: read_wheels(Path(directory))
        for target, directory in zip(TARGETS, sys.argv[1:3], strict=True)
    }
    package_sets = {target: set(packages) for target, packages in target_packages.items()}
    if package_sets[TARGETS[0]] != package_sets[TARGETS[1]]:
        missing = {
            target: sorted(package_sets[other] - package_sets[target])
            for target, other in (
                (TARGETS[0], TARGETS[1]),
                (TARGETS[1], TARGETS[0]),
            )
        }
        raise SystemExit(f"target dependency sets differ: {missing}")

    lines = [
        "# Generated from requirements.in for CPython 3.11 on Debian Bookworm.",
        "# Regenerate only with the digest-pinned Docker commands in README.md.",
    ]
    for name in sorted(package_sets[TARGETS[0]]):
        versions = {target_packages[target][name][0] for target in TARGETS}
        if len(versions) != 1:
            raise SystemExit(f"target versions differ for {name}: {sorted(versions)}")
        version = versions.pop()
        hashes = sorted(
            set().union(*(target_packages[target][name][1] for target in TARGETS))
        )
        lines.append(f"{name}=={version} \\")
        for index, digest in enumerate(hashes):
            suffix = " \\" if index < len(hashes) - 1 else ""
            lines.append(f"    --hash=sha256:{digest}{suffix}")

    Path(sys.argv[3]).write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
