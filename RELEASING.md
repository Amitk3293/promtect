# Releasing Promtect Core

Core releases are built from an immutable, reviewed `main` tag, but a tag never
publishes anything by itself. Candidate construction, GitHub Release
publication, container publication, and Homebrew tap updates are separate gates.
This prevents a partial matrix build or an accidental tag from becoming a public
release.

## Required repository controls

Promtect Core is maintained by a single person, so there is no second reviewer
and no environment approval in the release path. The authorization boundary is
the manual dispatch itself: a run publishes only when the maintainer sets
`publish` and retypes the exact tag. Everything that protects artifact integrity
is still enforced by the workflows and still fails closed.

Before the first public release:

- Make the Core and Homebrew tap repositories anonymously readable. Promtect Pro
  remains private and must never be included in a Core artifact.
- Configure an active repository ruleset for `refs/tags/v*` that restricts tag
  updates and deletion with **no bypass actors**. A published release must keep
  pointing at the commit it was built from, and this is the preventive control
  that guarantees it. The workflows also re-fetch and compare both the annotated
  tag object ID and its target commit immediately before any release or package
  mutation, but that is detection, not prevention.
- Require the full staging suite and an independent `/code-review` before
  promotion to `main`. A staging-to-main promotion must contain no unreviewed
  changes.
- Keep release tags annotated. Signed tags are preferred when the release
  operator has a configured signing identity; GitHub artifact attestations are
  mandatory for the four published archives.

Both publication workflows refuse to run unless they are dispatched from `main`,
the dispatched workflow commit is the exact commit the tag points at, and the tag
version matches `Cargo.toml`. Both workflows refuse to publish
from a private repository. An older tag therefore cannot reuse newer release
governance or execute its own older verifier scripts.

Until the anonymous-read checks are green, run candidate builds with
`publish=false` only.

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

That run builds and verifies its own candidate before the publish job starts;
artifacts are never promoted across runs. Because nobody else approves the run,
do the candidate inspection first: from the earlier `publish=false` run, download
`core-vX.Y.Z-verified`, compare its artifact digest with the verification job
summary, and inspect the archives, sidecars, embedded source SHA, and formula.
Dispatch the publishing run only once that candidate is acceptable. Core release
runs are serialized across tags so an older version cannot finish after a newer
version and move GitHub's `latest` marker backwards.

The publish job checks out the already validated commit, re-fetches the
remote annotated tag, and requires both its tag object ID and target commit to
remain unchanged. It downloads and reverifies the same-run artifact and creates
GitHub build-provenance attestations. An existing unpublished draft may have its
title, body, and prerelease state normalized, but only after the preflight binds
it to the reviewed tag/source and rejects a published release or unexpected
assets. The normalized draft is then verified against deterministic metadata
before upload. The job revalidates the tag, complete asset set, downloaded
assets, and target again before making the release public and marking it as
GitHub's latest stable release. It refuses to replace an existing published
release.

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
`main` workflow ref** with the same tag and `publish container vX.Y.Z`. Dispatch
it only when container distribution is intentionally in scope; the typed
confirmation is the whole gate. The job checks out the exact validated commit and
rejects a changed remote tag.

The build first pushes content by digest without a customer-facing tag. Only
after the build completes does the serialized job re-read grouped GHCR version
records, refuse an existing exact tag at another digest, and prove the current `X.Y` tag belongs
to the highest paired `X.Y.Z`/`vX.Y.Z` digest. The exact resolved digest must
return the expected version and pass `selftest` before any tag write. The job
then promotes that reviewed digest to the two exact tags and rolling minor tag. A bounded postcondition
requires both the package API and direct registry reads for all three tags to
resolve to the pushed digest. Missing or deleted provenance fails closed rather
than guessing from flattened tag history.

Before the first customer-facing tag write, the publish job stores the chosen
digest, tag, and exact source SHA in an immutable 90-day workflow artifact. A
retry selects the oldest unexpired record bound to that `main` source and reuses
its digest even when a fresh rebuild has another digest. An absent alias is
created, a same-digest alias is idempotently recreated, and any other digest
fails closed. A missing, expired, malformed, wrong-branch, or wrong-source record
cannot authorize recovery. This makes a partial multi-tag write recoverable
without permitting immutable version replacement.

GHCR does not provide a permanent immutable-tag guarantee. These controls
enforce non-replacement for this serialized workflow and detect publication
drift at completion; a separate actor with package write access could still move
or delete a tag later. Limit package writers, monitor tag-to-digest mappings,
and treat signed attestations/digest pins as the durable identity. If a recovery
record has expired while an orphan alias remains, stop and use a separately
reviewed package-administration cleanup; a new patch must not bypass the orphan
provenance check.

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
