#!/usr/bin/env python3
"""Fail closed unless the repository release controls are fully configured."""

import argparse
import json
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"release control verification error: {message}")


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


def verify_environment(
    name: str,
    environment_path: Path,
    policies_path: Path,
    expected_reviewer_ids: set[int],
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
    if len(reviewers) != len(expected_reviewer_ids) or not all(
        isinstance(reviewer, dict)
        and reviewer.get("type") in {"User", "Team"}
        and isinstance(reviewer.get("reviewer"), dict)
        and isinstance(reviewer["reviewer"].get("id"), int)
        for reviewer in reviewers
    ):
        fail(f"{name} contains an invalid or duplicate required reviewer")
    actual_reviewer_ids = {
        reviewer.get("reviewer", {}).get("id")
        for reviewer in reviewers
        if isinstance(reviewer, dict)
        and isinstance(reviewer.get("reviewer"), dict)
        and isinstance(reviewer["reviewer"].get("id"), int)
    }
    if actual_reviewer_ids != expected_reviewer_ids:
        fail(f"{name} required reviewers do not match the approved reviewer IDs")
    prevent_self_review = reviewer_rules[0].get(
        "prevent_self_review", environment.get("prevent_self_review")
    )
    if prevent_self_review is False:
        fail(f"{name} allows the publisher to approve their own deployment")

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


def verify_tag_ruleset(
    rulesets: list[dict[str, Any]], expected_bypass_actor_ids: set[int]
) -> None:
    required_rules = {"creation", "update", "deletion"}
    for ruleset in rulesets:
        if ruleset.get("target") != "tag" or ruleset.get("enforcement") != "active":
            continue
        conditions = ruleset.get("conditions")
        ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
        includes = ref_name.get("include") if isinstance(ref_name, dict) else None
        excludes = ref_name.get("exclude") if isinstance(ref_name, dict) else None
        if not isinstance(includes, list) or "refs/tags/v*" not in includes:
            continue
        if excludes != []:
            continue
        rules = ruleset.get("rules")
        if not isinstance(rules, list):
            continue
        rule_types = {
            rule.get("type") for rule in rules if isinstance(rule, dict)
        }
        bypass_actors = ruleset.get("bypass_actors")
        if not isinstance(bypass_actors, list) or not bypass_actors:
            continue
        if len(bypass_actors) != len(expected_bypass_actor_ids):
            continue
        if not all(
            isinstance(actor, dict)
            and isinstance(actor.get("actor_id"), int)
            and isinstance(actor.get("actor_type"), str)
            and actor.get("bypass_mode") == "always"
            for actor in bypass_actors
        ):
            continue
        actual_actor_ids = {
            actor.get("actor_id")
            for actor in bypass_actors
            if isinstance(actor.get("actor_id"), int)
        }
        if actual_actor_ids != expected_bypass_actor_ids:
            continue
        if required_rules.issubset(rule_types):
            return
    fail(
        "no active refs/tags/v* ruleset blocks creation, updates, and deletion "
        "for everyone except explicit always-bypass release operators"
    )


parser = argparse.ArgumentParser()
parser.add_argument("--core-release", type=Path, required=True)
parser.add_argument("--core-release-policies", type=Path, required=True)
parser.add_argument("--core-container-release", type=Path, required=True)
parser.add_argument("--core-container-release-policies", type=Path, required=True)
parser.add_argument("--rulesets", type=Path, required=True)
parser.add_argument("--expected-bypass-actor-ids", required=True)
parser.add_argument("--expected-reviewer-ids", required=True)
args = parser.parse_args()

try:
    expected_bypass_actor_ids = {
        int(item) for item in args.expected_bypass_actor_ids.split(",") if item
    }
except ValueError:
    fail("expected bypass actor IDs must be comma-separated integers")
if not expected_bypass_actor_ids:
    fail("at least one expected release-operator bypass actor ID is required")
try:
    expected_reviewer_ids = {
        int(item) for item in args.expected_reviewer_ids.split(",") if item
    }
except ValueError:
    fail("expected reviewer IDs must be comma-separated integers")
if not expected_reviewer_ids:
    fail("at least one expected release reviewer ID is required")

verify_environment(
    "core-release",
    args.core_release,
    args.core_release_policies,
    expected_reviewer_ids,
)
verify_environment(
    "core-container-release",
    args.core_container_release,
    args.core_container_release_policies,
    expected_reviewer_ids,
)
verify_tag_ruleset(load_rulesets(args.rulesets), expected_bypass_actor_ids)
print("release controls verified: environments, reviewers, main-only access, tag ruleset")
