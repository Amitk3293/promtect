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
  `core-container-release` with required reviewers. The workflows also require
  exact typed confirmation; environment protection is the human authorization
  boundary.
- Configure an active repository ruleset for `refs/tags/v*` that restricts tag
  creation to release operators and prevents tag updates and deletion. The
  workflows re-fetch and compare both the annotated tag object ID and commit
  after every environment wait, but the ruleset is the preventive control.
- Require the full staging suite and independent `/code-review` before promotion
  to `main`. A staging-to-main promotion must contain no unreviewed changes.
- Keep release tags annotated. Signed tags are preferred when the release
  operator has a configured signing identity; GitHub artifact attestations are
  mandatory for the four published archives.

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

- `tag`: the existing annotated `vX.Y.Z` tag;
- `publish`: `false`;
- no publication confirmation.

The workflow verifies that the tag version matches `Cargo.toml` and that the tag
is contained in `main`. It runs the Docker readiness gate, then builds:

- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`

Each matrix job uploads only a candidate artifact. A single verification job
downloads all four, rejects incomplete/mixed-source sets, validates immutable
SHA-256 sidecars and embedded source metadata, and produces a reviewable
`promtect.rb`. Nothing is released and the tap is not changed.

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
run.

After approval, the job checks out the already validated commit, re-fetches the
remote annotated tag, and requires both its tag object ID and target commit to
remain unchanged. It downloads and reverifies the same-run artifact, creates
GitHub build-provenance attestations, and validates an existing draft's exact
target before any upload. It revalidates the tag, draft identity, downloaded
assets, and target again before making the release public. It refuses to replace
an existing published release.

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

Open a separate reviewed PR in `Amitk3293/homebrew-tap`; release CI never pushes
the tap. Run `brew audit --strict`, `brew install --build-from-source`,
`brew test`, `promtect --version`, and `promtect selftest` in a clean Homebrew
Docker environment before merging the formula. Finally repeat
`brew install Amitk3293/tap/promtect` anonymously from a clean environment.

## Optional container publication

The GHCR image is not part of the Homebrew release and is never triggered by a
tag. Dispatch `.github/workflows/docker-publish.yml` separately with the same
tag and `publish container vX.Y.Z`; approve the `core-container-release`
environment only when container distribution is intentionally in scope. The
job checks out the exact pre-approval commit and rejects a changed remote tag.
Exact `X.Y.Z` and `vX.Y.Z` image tags are immutable: an existing tag aborts the
run. The shared `X.Y` tag advances only when the incoming patch is newer than
every immutable patch tag already published on that release line; all container
publications are serialized to prevent two patch releases from racing. A failed
or repeated publication requires a new patch version, never tag replacement.

## Versioning

The tracked pre-commit hook increments the patch version for Core code changes.
Enable it once per clone:

```sh
git config core.hooksPath .githooks
```

The hook changes only the patch component. Bump minor or major deliberately when
the release contract warrants it.
