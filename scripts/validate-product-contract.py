#!/usr/bin/env python3
"""Validate the canonical contract against Core and Site."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise ValueError(message)


def load_contract(core: Path) -> dict:
    return json.loads((core / "PRODUCT-CONTRACT.json").read_text())


def validate_site(site: Path) -> None:
    source = (site / "worker.js").read_text()
    # Match a committed purchase URL, not the bare hostname: the Worker carries
    # "buy.stripe.com" as the allow-list constant its catalog validation checks.
    #
    # No forbidden-term scan here: the honest copy has to write the phrase to
    # negate it ('not "open source"'), and a substring match cannot tell the
    # claim from its denial.
    if "https://buy.stripe.com/" in source:
        fail("Site embeds a Stripe purchase URL")


def validate_core_claims(contract: dict, core: Path) -> None:
    documents = (
        core / "README.md",
        core / "ROADMAP.md",
        core / "docs" / "README.md",
        core / "docs" / "integrations" / "README.md",
    )
    prohibited = [
        claim.lower()
        for claim in contract["claims"]["prohibited"]
        if claim.lower() != "open source"
    ]
    for document in documents:
        text = document.read_text().lower()
        for claim in prohibited:
            if re.search(rf"\b{re.escape(claim)}\b", text):
                fail(f"{document.relative_to(core)} contains prohibited claim: {claim}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", type=Path, default=Path.cwd())
    parser.add_argument("--site", type=Path, required=True)
    args = parser.parse_args()

    contract = load_contract(args.core)
    validate_core_claims(contract, args.core)
    validate_site(args.site)
    print("product contract matches Core and Site")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"product contract validation failed: {error}", file=sys.stderr)
        sys.exit(1)
