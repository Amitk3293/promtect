#!/usr/bin/env bash
# Fetch and verify the read-only GitHub controls that protect publication jobs.
set -euo pipefail

fail() { echo "release control preflight error: $1" >&2; exit 1; }

repository="${1:-${GITHUB_REPOSITORY:-}}"
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
  || fail "repository must be owner/name"
[ -n "${GH_TOKEN:-}" ] \
  || fail "GH_TOKEN with read access to environments and rulesets is required"
[ -n "${PROMTECT_RELEASE_BYPASS_ACTOR_IDS:-}" ] \
  || fail "PROMTECT_RELEASE_BYPASS_ACTOR_IDS is required"
[ -n "${PROMTECT_RELEASE_REVIEWER_IDS:-}" ] \
  || fail "PROMTECT_RELEASE_REVIEWER_IDS is required"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
evidence_args=()
if [ -n "${PROMTECT_ADMIN_BYPASS_EVIDENCE_JSON:-}" ]; then
  printf '%s\n' "$PROMTECT_ADMIN_BYPASS_EVIDENCE_JSON" \
    > "$root/admin-bypass-evidence.json"
  evidence_args=(
    --manual-admin-bypass-evidence "$root/admin-bypass-evidence.json"
  )
fi

for environment in core-release core-container-release; do
  gh api "/repos/${repository}/environments/${environment}" \
    > "$root/${environment}.json" \
    || fail "${environment} is absent or cannot be inspected"
  gh api \
    "/repos/${repository}/environments/${environment}/deployment-branch-policies?per_page=100" \
    > "$root/${environment}-policies.json" \
    || fail "${environment} deployment policies cannot be inspected"
done

gh api --paginate --slurp "/repos/${repository}/rulesets?per_page=100" \
  > "$root/ruleset-pages.json" \
  || fail "repository rulesets cannot be inspected"

python3 - "$root/ruleset-pages.json" > "$root/ruleset-ids" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    pages = json.load(handle)
for page in pages:
    if not isinstance(page, list):
        raise SystemExit("ruleset summary page is not a list")
    for ruleset in page:
        identifier = ruleset.get("id") if isinstance(ruleset, dict) else None
        if not isinstance(identifier, int):
            raise SystemExit("ruleset summary has no numeric id")
        print(identifier)
PY

: > "$root/rulesets.jsonl"
while IFS= read -r ruleset_id; do
  gh api "/repos/${repository}/rulesets/${ruleset_id}" \
    >> "$root/rulesets.jsonl" \
    || fail "ruleset ${ruleset_id} cannot be inspected"
  printf '\n' >> "$root/rulesets.jsonl"
done < "$root/ruleset-ids"

python3 - "$root/rulesets.jsonl" > "$root/rulesets.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.dumps([json.loads(line) for line in handle if line.strip()]))
PY

python3 scripts/verify-github-release-controls.py \
  --core-release "$root/core-release.json" \
  --core-release-policies "$root/core-release-policies.json" \
  --core-container-release "$root/core-container-release.json" \
  --core-container-release-policies "$root/core-container-release-policies.json" \
  --rulesets "$root/rulesets.json" \
  --expected-bypass-actor-ids "$PROMTECT_RELEASE_BYPASS_ACTOR_IDS" \
  --expected-reviewer-ids "$PROMTECT_RELEASE_REVIEWER_IDS" \
  --repository "$repository" \
  "${evidence_args[@]}"
