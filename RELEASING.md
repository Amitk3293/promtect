# Releasing Promtect Core

Core releases are built from an immutable, reviewed `main` tag, but a tag never
publishes anything by itself. Candidate construction, GitHub Release
publication, container publication, and Homebrew tap updates are separate gates.
This prevents a partial matrix build or an accidental tag from becoming a public
release.

## Required repository controls

Before the first public release:

- Make the Core and Homebrew tap repositories anonymously readable. Promtect Pro
  remains private and must never be included in a Core artifact.
- Configure the GitHub environments `core-release` and
  `core-container-release` with required reviewers and a single custom
  deployment-branch policy for `main`. `prevent_self_review` must be the exact
  boolean `true`, and **Allow administrators to bypass configured protection
  rules** must be disabled. The workflows also require exact typed confirmation;
  environment protection is the human authorization boundary.
- Configure an active repository ruleset for `refs/tags/v*` that restricts tag
  creation to release operators and prevents tag updates and deletion. The
  workflows re-fetch and compare both the annotated tag object ID and commit
  after every environment wait, but the ruleset is the preventive control.
- Require the full staging suite and independent `/code-review` before promotion
  to `main`. A staging-to-main promotion must contain no unreviewed changes.
- Keep release tags annotated. Signed tags are preferred when the release
  operator has a configured signing identity; GitHub artifact attestations are
  mandatory for the four published archives.
- Add a read-only fine-grained `RELEASE_READINESS_TOKEN` Actions secret that can
  inspect environments and repository rulesets. Add repository variables
  `RELEASE_REVIEWERS` and `RELEASE_BYPASS_ACTORS` containing
  the exact approved GitHub actor types and numeric IDs as comma-separated
  `Type:id` entries (for example, `User:123` or `RepositoryRole:5`). The workflows
  compare both fields so a same-number actor of another type cannot satisfy the
  gate. They only issue GET requests with this token; control provisioning
  remains a manual administrator action.
- Record a fresh `RELEASE_ADMIN_BYPASS_EVIDENCE` repository variable when the
  GitHub environment API does not expose an administrator-bypass field. The
  compact JSON record must be valid for no more than 24 hours, be recorded by an
  approved reviewer, bind both environment `updated_at` values, state that
  administrator bypass is disabled, and reference a private screenshot or
  recording plus its SHA-256:

  ```json
  {"schema_version":1,"repository":"Amitk3293/promtect","source":"github-environment-settings-ui","evidence_reference":"https://github.com/Amitk3293/promtect/issues/ISSUE#issuecomment-COMMENT","evidence_sha256":"64-lowercase-hex-characters","recorded_by_reviewer_type":"User","recorded_by_reviewer_id":123,"recorded_at":"2026-07-13T19:00:00Z","expires_at":"2026-07-13T20:00:00Z","environments":{"core-release":{"administrators_can_bypass":false,"updated_at":"API-updated-at"},"core-container-release":{"administrators_can_bypass":false,"updated_at":"API-updated-at"}}}
  ```

Both publication workflows verify every API-visible control before a protected
environment is referenced, so a missing environment cannot be silently
auto-created as the authorization boundary. They verify the same state again
immediately after approval and before any release or package mutation. A future
API administrator-bypass field must be the exact boolean `false`; any other
value fails closed. When that field is absent, the workflow validates the fresh
manual record above against the current API timestamps.

This record is manual launch-gate evidence, not automatic proof of the UI
setting. GitHub documents that administrators can bypass environment rules by
default and that an environment can disable that bypass, but the REST OpenAPI
schema retrieved on 2026-07-13 exposes `prevent_self_review` and does not expose
the administrator-bypass setting. The evidence expiry and `updated_at` binding
limit staleness; an approved human must still inspect the referenced capture.
See [Deployments and environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments),
[Reviewing deployments](https://docs.github.com/en/actions/managing-workflow-runs/reviewing-deployments),
and the [official REST description](https://github.com/github/rest-api-description).
Missing credentials, controls, exact actors, evidence, or a main-only deployment
policy fails closed.

Until those controls and anonymous-read checks are green, run candidate builds
with `publish=false` only.

## 1. Verify the staging candidate in Docker

Every local Promtect build, package, install, and selftest runs in Docker:

```sh
make docker-test
make provider-harness
make dashboard-browser-test
make release-readiness-test
```

`release-readiness-test` builds Core from the locked dependency graph, packages
the release layout twice to prove deterministic archive metadata, verifies the
manifest and checksums, performs a clean extraction/install, runs `--version`
and `selftest`, generates and parses the formula, and proves checksum tampering
and path traversal are rejected.

## 2. Promote reviewed staging and create the tag

After the complete staging suite passes, promote that exact reviewed commit to
`main`. Confirm the version in `Cargo.toml`, then create one annotated tag at the
promoted commit:

```sh
git tag -a vX.Y.Z <reviewed-main-sha> -m "Promtect vX.Y.Z"
git push origin vX.Y.Z
```

Pushing the tag does not start either publication workflow.

## 3. Build a private release candidate

Manually dispatch `.github/workflows/release.yml` with:

- workflow ref: `main` (any other selected ref fails before candidate work);
- `tag`: the existing annotated `vX.Y.Z` tag;
- `publish`: `false`;
- no publication confirmation.

The workflow verifies that the tag version matches `Cargo.toml` and that the tag
points at the exact `main` commit containing the dispatched workflow. Older tags
cannot reuse newer release governance or execute their own older verifier scripts.
It runs the Docker readiness gate, then builds:

- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`

Each target is built and executed on a pinned native runner before upload. The
packaged binary must return the exact version and pass `selftest`. Linux builds
currently declare their build-host compatibility floor through pinned runners:
Ubuntu 22.04/glibc 2.35 for both x86-64 and ARM64. Lower
floors require a separately tested build environment; they must not be claimed
from header-only inspection.

Each matrix job uploads only a smoke-tested candidate artifact. A single verification job
downloads all four, rejects incomplete/mixed-source sets, validates immutable
SHA-256 sidecars, requires every embedded source SHA to equal the validated tag
commit, and produces a reviewable `promtect.rb`. Nothing is released and the tap
is not changed.

## 4. Publish the verified Core archives

Candidate-only artifacts are useful rehearsal evidence, but they are not later
promoted across workflow runs. To publish, dispatch a new workflow run with:

- `publish`: `true`;
- `publish_confirmation`: `publish vX.Y.Z`.

That run builds and verifies its own candidate before the protected `core-release`
job becomes eligible for approval. The reviewer must download
`core-vX.Y.Z-verified` from that same run, compare its artifact digest with the
verification job summary, inspect the archives, sidecars, embedded source SHA,
and formula, and only then approve the environment. Reject the job if the
candidate is not acceptable; never approve based on an artifact from another
run. Core release runs are serialized across tags so an older version cannot
finish after a newer version and move GitHub's `latest` marker backwards.

After approval, the job checks out the already validated commit, re-fetches the
remote annotated tag, and requires both its tag object ID and target commit to
remain unchanged. It downloads and reverifies the same-run artifact, creates
GitHub build-provenance attestations, and normalizes an existing draft to a
deterministic title and marker-bound body before any upload. It rejects
unexpected draft assets, prerelease state, or metadata drift. It revalidates the
tag, complete asset set, deterministic metadata, downloaded assets, and target
again before making the release public and marking it as GitHub's latest stable
release. It refuses to replace an existing published release.

Do not delete or replace a published asset. If an artifact is wrong, fix the
problem and publish a new patch version.

## 5. Validate anonymous acquisition and update Homebrew

From a clean, unauthenticated Docker environment, verify every archive URL and
sidecar, checksum the downloads, extract the native Linux archive, and run:

```sh
promtect --version
promtect selftest
```

Generate the formula from the published sidecars:

```sh
scripts/update-formula.sh vX.Y.Z > promtect.rb
```

The generator accepts only a stable `vX.Y.Z` tag and an `owner/repository`
`PROMTECT_REPO` value before either is interpolated into formula text.

Open a separate reviewed PR in `Amitk3293/homebrew-tap`; release CI never pushes
the tap. Run `brew audit --strict`, `brew install --build-from-source`,
`brew test`, `promtect --version`, and `promtect selftest` in a clean Homebrew
Docker environment before merging the formula. Finally repeat
`brew install Amitk3293/tap/promtect` anonymously from a clean environment.

## Optional container publication

The GHCR image is not part of the Homebrew release and is never triggered by a
tag. Dispatch `.github/workflows/docker-publish.yml` separately **from the
`main` workflow ref** with the same tag and `publish container vX.Y.Z`; approve
the `core-container-release` environment only when container distribution is
intentionally in scope. The job checks out the exact pre-approval commit and
rejects a changed remote tag.

The build first pushes content by digest without a customer-facing tag. Only
after the build completes does the serialized job re-read grouped GHCR version
records, refuse an existing exact tag at another digest, and prove the current `X.Y` tag belongs
to the highest paired `X.Y.Z`/`vX.Y.Z` digest. It then promotes that reviewed
digest to the two exact tags and rolling minor tag. A bounded postcondition
requires both the package API and direct registry reads for all three tags to
resolve to the pushed digest. Missing or deleted provenance fails closed rather
than guessing from flattened tag history.

If a tag promotion is interrupted, a retry may resume only aliases that already
resolve to the exact digest pushed by that retry. An absent alias is created, a
same-digest alias is idempotently recreated, and any other digest fails closed.
This makes a partial multi-tag write recoverable without permitting immutable
version replacement.

GHCR does not provide a permanent immutable-tag guarantee. These controls
enforce non-replacement for this serialized workflow and detect publication
drift at completion; a separate actor with package write access could still move
or delete a tag later. Limit package writers, monitor tag-to-digest mappings,
and treat signed attestations/digest pins as the durable identity. A failure that
cannot prove same-digest partial state requires a new patch version, never
intentional tag replacement.

The conventional container `latest` tag is deprecated and is never published or
advanced. Consumers must pin `X.Y.Z`, `vX.Y.Z`, or deliberately track `X.Y`.
Publication fails while a legacy `latest` tag exists, so the current stale tag
must be removed through a separately reviewed repository-administration action
before the first run of this workflow.

## Versioning

The tracked pre-commit hook increments the patch version for Core code changes.
Enable it once per clone:

```sh
git config core.hooksPath .githooks
```

The hook changes only the patch component. Bump minor or major deliberately when
the release contract warrants it.
