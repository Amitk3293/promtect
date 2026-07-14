#!/usr/bin/env python3
"""Fail closed unless the repository release controls are fully configured."""

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"release control verification error: {message}")


def parse_actor_set(
    value: str, description: str, allowed_types: set[str]
) -> set[tuple[str, int]]:
    actors: set[tuple[str, int]] = set()
    for item in value.split(","):
        parts = item.strip().split(":", 1)
        if len(parts) != 2 or parts[0] not in allowed_types:
            fail(f"{description} must use comma-separated Type:numeric-id entries")
        actor_type, identifier_text = parts
        if re.fullmatch(r"[1-9][0-9]*", identifier_text) is None:
            fail(f"{description} contains an invalid numeric actor ID")
        actor = (actor_type, int(identifier_text))
        if actor in actors:
            fail(f"{description} contains a duplicate actor")
        actors.add(actor)
    if not actors:
        fail(f"at least one {description} entry is required")
    return actors


def load_object(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid {description} response: {error}")
    if not isinstance(value, dict):
        fail(f"{description} response is not an object")
    return value


def load_rulesets(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid rulesets response: {error}")
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        fail("rulesets response is not an object list")
    return value


def parse_timestamp(value: Any, description: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{description} must be an RFC 3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        fail(f"{description} is invalid: {error}")
    if parsed.tzinfo != timezone.utc:
        fail(f"{description} must use UTC")
    return parsed


def admin_bypass_values(value: Any) -> list[Any]:
    """Find any current or future API field whose name describes admin bypass."""
    found: list[Any] = []
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            if "admin" in normalized and "bypass" in normalized:
                found.append(child)
            found.extend(admin_bypass_values(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(admin_bypass_values(child))
    return found


def verify_manual_admin_bypass_evidence(
    name: str,
    environment: dict[str, Any],
    evidence: dict[str, Any] | None,
    expected_repository: str,
    expected_reviewers: set[tuple[str, int]],
    now: datetime,
) -> None:
    if evidence is None:
        fail(
            f"{name} API response has no administrator-bypass field and fresh "
            "manual launch-gate evidence is absent"
        )
    if evidence.get("schema_version") != 1:
        fail("manual administrator-bypass evidence has an unsupported schema")
    if evidence.get("repository") != expected_repository:
        fail("manual administrator-bypass evidence is for the wrong repository")
    if evidence.get("source") != "github-environment-settings-ui":
        fail("manual administrator-bypass evidence has an invalid source")
    evidence_reference = evidence.get("evidence_reference")
    expected_reference_prefix = f"https://github.com/{expected_repository}/"
    if not isinstance(evidence_reference, str) or not evidence_reference.startswith(
        expected_reference_prefix
    ):
        fail("manual administrator-bypass evidence reference is invalid")
    evidence_sha256 = evidence.get("evidence_sha256")
    if not isinstance(evidence_sha256, str) or re.fullmatch(
        r"[0-9a-f]{64}", evidence_sha256
    ) is None:
        fail("manual administrator-bypass evidence SHA-256 is invalid")
    reviewer = (
        evidence.get("recorded_by_reviewer_type"),
        evidence.get("recorded_by_reviewer_id"),
    )
    if reviewer not in expected_reviewers:
        fail("manual administrator-bypass evidence was recorded by an unapproved reviewer")

    recorded_at = parse_timestamp(evidence.get("recorded_at"), "evidence recorded_at")
    expires_at = parse_timestamp(evidence.get("expires_at"), "evidence expires_at")
    if expires_at <= recorded_at or expires_at - recorded_at > timedelta(hours=24):
        fail("manual administrator-bypass evidence validity must be 24 hours or less")
    if now < recorded_at or now > expires_at:
        fail("manual administrator-bypass evidence is not currently valid")

    environments = evidence.get("environments")
    if not isinstance(environments, dict) or set(environments) != {
        "core-release",
        "core-container-release",
    }:
        fail("manual administrator-bypass evidence has the wrong environment set")
    recorded_environment = environments.get(name)
    if not isinstance(recorded_environment, dict):
        fail(f"manual administrator-bypass evidence for {name} is invalid")
    if recorded_environment.get("administrators_can_bypass") is not False:
        fail(f"manual evidence does not record administrator bypass disabled for {name}")
    updated_at = environment.get("updated_at")
    if not isinstance(updated_at, str) or recorded_environment.get("updated_at") != updated_at:
        fail(f"manual evidence does not match the current {name} configuration timestamp")


def verify_environment(
    name: str,
    environment_path: Path,
    policies_path: Path,
    expected_reviewers: set[tuple[str, int]],
    manual_admin_bypass_evidence: dict[str, Any] | None,
    expected_repository: str,
    now: datetime,
) -> None:
    environment = load_object(environment_path, f"{name} environment")
    if environment.get("name") != name:
        fail(f"{name} environment is absent or has the wrong name")

    protection_rules = environment.get("protection_rules")
    if not isinstance(protection_rules, list):
        fail(f"{name} protection rules are absent")
    reviewer_rules = [
        rule
        for rule in protection_rules
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    if len(reviewer_rules) != 1:
        fail(f"{name} must have exactly one required-reviewers rule")
    reviewers = reviewer_rules[0].get("reviewers")
    if not isinstance(reviewers, list) or not reviewers:
        fail(f"{name} has no required reviewer")
    if len(reviewers) != len(expected_reviewers) or not all(
        isinstance(reviewer, dict)
        and reviewer.get("type") in {"User", "Team"}
        and isinstance(reviewer.get("reviewer"), dict)
        and isinstance(reviewer["reviewer"].get("id"), int)
        for reviewer in reviewers
    ):
        fail(f"{name} contains an invalid or duplicate required reviewer")
    actual_reviewers = {
        (reviewer.get("type"), reviewer.get("reviewer", {}).get("id"))
        for reviewer in reviewers
        if isinstance(reviewer, dict)
        and isinstance(reviewer.get("reviewer"), dict)
        and isinstance(reviewer["reviewer"].get("id"), int)
    }
    if actual_reviewers != expected_reviewers:
        fail(f"{name} required reviewers do not match the approved reviewer IDs")
    if reviewer_rules[0].get("prevent_self_review") is not True:
        fail(f"{name} must set prevent_self_review to boolean true")

    bypass_values = admin_bypass_values(environment)
    if bypass_values:
        if any(value is not False for value in bypass_values):
            fail(f"{name} administrator-bypass API field must be boolean false")
    else:
        verify_manual_admin_bypass_evidence(
            name,
            environment,
            manual_admin_bypass_evidence,
            expected_repository,
            expected_reviewers,
            now,
        )

    branch_policy = environment.get("deployment_branch_policy")
    if not isinstance(branch_policy, dict):
        fail(f"{name} has no deployment branch policy")
    if branch_policy.get("protected_branches") is not False:
        fail(f"{name} must use an explicit main-only branch policy")
    if branch_policy.get("custom_branch_policies") is not True:
        fail(f"{name} custom deployment branch policies are disabled")

    policy_response = load_object(policies_path, f"{name} branch policies")
    policies = policy_response.get("branch_policies")
    if not isinstance(policies, list):
        fail(f"{name} branch policy list is absent")
    normalized = {
        (policy.get("name"), policy.get("type"))
        for policy in policies
        if isinstance(policy, dict)
    }
    if len(policies) != 1 or normalized != {("main", "branch")}:
        fail(f"{name} deployment access must be restricted to the main branch")


def tag_ruleset_scope(ruleset: dict[str, Any]) -> set[str] | None:
    if ruleset.get("target") != "tag" or ruleset.get("enforcement") != "active":
        return None
    conditions = ruleset.get("conditions")
    ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
    includes = ref_name.get("include") if isinstance(ref_name, dict) else None
    excludes = ref_name.get("exclude") if isinstance(ref_name, dict) else None
    if not isinstance(includes, list) or "refs/tags/v*" not in includes:
        return None
    if excludes != []:
        return None
    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        return None
    return {rule.get("type") for rule in rules if isinstance(rule, dict)}


def verify_tag_rulesets(
    rulesets: list[dict[str, Any]], expected_bypass_actors: set[tuple[str, int]]
) -> None:
    creation_verified = False
    immutability_verified = False
    for ruleset in rulesets:
        rule_types = tag_ruleset_scope(ruleset)
        if rule_types is None:
            continue
        bypass_actors = ruleset.get("bypass_actors")
        if not isinstance(bypass_actors, list):
            continue

        if (
            "creation" in rule_types
            and "update" not in rule_types
            and "deletion" not in rule_types
            and len(bypass_actors) == len(expected_bypass_actors)
            and all(
                isinstance(actor, dict)
                and isinstance(actor.get("actor_id"), int)
                and actor.get("actor_type")
                in {"Integration", "RepositoryRole", "Team", "User"}
                and actor.get("bypass_mode") == "always"
                for actor in bypass_actors
            )
        ):
            actual_actors = {
                (actor.get("actor_type"), actor.get("actor_id"))
                for actor in bypass_actors
                if isinstance(actor.get("actor_id"), int)
            }
            creation_verified = (
                creation_verified or actual_actors == expected_bypass_actors
            )

        if (
            {"update", "deletion"}.issubset(rule_types)
            and "creation" not in rule_types
            and bypass_actors == []
        ):
            immutability_verified = True

    if not creation_verified:
        fail(
            "no active refs/tags/v* creation-only ruleset permits exactly the "
            "approved always-bypass release operators"
        )
    if not immutability_verified:
        fail(
            "no separate active refs/tags/v* ruleset blocks tag updates and "
            "deletion without bypass actors"
        )


parser = argparse.ArgumentParser()
parser.add_argument("--core-release", type=Path, required=True)
parser.add_argument("--core-release-policies", type=Path, required=True)
parser.add_argument("--core-container-release", type=Path, required=True)
parser.add_argument("--core-container-release-policies", type=Path, required=True)
parser.add_argument("--rulesets", type=Path, required=True)
parser.add_argument("--expected-bypass-actors", required=True)
parser.add_argument("--expected-reviewers", required=True)
parser.add_argument("--repository", required=True)
parser.add_argument("--manual-admin-bypass-evidence", type=Path)
parser.add_argument("--now")
args = parser.parse_args()

expected_bypass_actors = parse_actor_set(
    args.expected_bypass_actors,
    "expected tag-creation operator bypass actors",
    {"Integration", "RepositoryRole", "Team", "User"},
)
expected_reviewers = parse_actor_set(
    args.expected_reviewers,
    "expected release reviewers",
    {"Team", "User"},
)
if not args.repository or "/" not in args.repository:
    fail("repository must be owner/name")

manual_admin_bypass_evidence = (
    load_object(args.manual_admin_bypass_evidence, "manual administrator-bypass evidence")
    if args.manual_admin_bypass_evidence is not None
    else None
)
now = (
    parse_timestamp(args.now, "current time")
    if args.now is not None
    else datetime.now(timezone.utc)
)

verify_environment(
    "core-release",
    args.core_release,
    args.core_release_policies,
    expected_reviewers,
    manual_admin_bypass_evidence,
    args.repository,
    now,
)
verify_environment(
    "core-container-release",
    args.core_container_release,
    args.core_container_release_policies,
    expected_reviewers,
    manual_admin_bypass_evidence,
    args.repository,
    now,
)
verify_tag_rulesets(load_rulesets(args.rulesets), expected_bypass_actors)
print(
    "release controls verified: environments, reviewers, main-only access, "
    "tag creation and immutable-tag rulesets"
)
