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


# The Site substitutes prices into its HTML at request time, so its deployable
# source carries tokens, never price literals. Each pair is the visible copy the
# token must still reach, and the binding that must still tie it to the contract.
SITE_PRICE_COPY = (
    ("$__PRO_MONTHLY__", '"__PRO_MONTHLY__": PRODUCT_CONTRACT.pricing_usd.pro.monthly_per_developer'),
    ("$__PRO_ANNUAL__/yr", '"__PRO_ANNUAL__": PRODUCT_CONTRACT.pricing_usd.pro.annual_per_developer'),
    ("$__TEAM_MONTHLY__", '"__TEAM_MONTHLY__": PRODUCT_CONTRACT.pricing_usd.team.monthly_per_developer'),
    ("$__TEAM_ANNUAL__/dev-yr", '"__TEAM_ANNUAL__": PRODUCT_CONTRACT.pricing_usd.team.annual_per_developer'),
    ("__TEAM_MIN_SEATS__ seats min", '"__TEAM_MIN_SEATS__": PRODUCT_CONTRACT.pricing_usd.team.minimum_seats'),
)


def validate_site(contract: dict, site: Path) -> None:
    source = (site / "worker.js").read_text()
    missing = [text for pair in SITE_PRICE_COPY for text in pair if text not in source]
    if missing:
        fail(f"Site pricing copy drifted from the contract tokens: missing {missing}")
    # Match a committed purchase URL, not the bare hostname: the Worker carries
    # "buy.stripe.com" as the allow-list constant its catalog validation checks.
    if not contract["pricing_usd"]["checkout_enabled"] and "https://buy.stripe.com/" in source:
        fail("checkout is disabled but Site still embeds a Stripe purchase URL")


def validate_core_claims(contract: dict, core: Path) -> None:
    documents = (
        core / "README.md",
        core / "COMMERCIAL.md",
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
    validate_site(contract, args.site)
    print("product contract matches Core and Site")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"product contract validation failed: {error}", file=sys.stderr)
        sys.exit(1)
