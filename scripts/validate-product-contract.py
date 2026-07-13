#!/usr/bin/env python3
"""Validate the canonical contract against Core, Site, and License Worker."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path


def fail(message: str) -> None:
    raise ValueError(message)


def load_contract(core: Path) -> dict:
    return json.loads((core / "PRODUCT-CONTRACT.json").read_text())


def expected_price_map(contract: dict, environment: str) -> dict[str, str]:
    pricing = contract["pricing_usd"]
    return {
        pricing[tier]["price_ids"][environment][period]: tier
        for tier in ("pro", "team")
        for period in ("monthly", "annual")
    }


def validate_worker(contract: dict, worker: Path) -> None:
    config = tomllib.loads((worker / "wrangler.toml").read_text())
    live = json.loads(config["vars"]["PRICE_TIER_MAP"])
    staging = json.loads(config["env"]["staging"]["vars"]["PRICE_TIER_MAP"])
    if live != expected_price_map(contract, "live"):
        fail("Worker production PRICE_TIER_MAP drifted from PRODUCT-CONTRACT.json")
    if staging != expected_price_map(contract, "staging"):
        fail("Worker staging PRICE_TIER_MAP drifted from PRODUCT-CONTRACT.json")


def validate_site(contract: dict, site: Path) -> None:
    source = (site / "worker.js").read_text()
    pricing = contract["pricing_usd"]
    required_copy = (
        f'${pricing["pro"]["monthly_per_developer"]}',
        f'${pricing["pro"]["annual_per_developer"]}/yr',
        f'${pricing["team"]["monthly_per_developer"]}',
        f'${pricing["team"]["annual_per_developer"]}/dev-yr',
        f'{pricing["team"]["minimum_seats"]} seats min',
    )
    missing = [text for text in required_copy if text not in source]
    if missing:
        fail(f"Site pricing copy drifted from contract: missing {missing}")
    if not pricing["checkout_enabled"] and "buy.stripe.com" in source:
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
    parser.add_argument("--worker", type=Path, required=True)
    args = parser.parse_args()

    contract = load_contract(args.core)
    validate_core_claims(contract, args.core)
    validate_site(contract, args.site)
    validate_worker(contract, args.worker)
    print("product contract matches Core, Site, and License Worker")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        print(f"product contract validation failed: {error}", file=sys.stderr)
        sys.exit(1)
