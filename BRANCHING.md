# Branching & releases — promtect

Two long-lived branches plus version tags. A CLI's "production" is a **tagged
release** (binaries + Homebrew), not a server deploy — so `main` is the released
line and tags are the cut points.

```
feature/* ──PR──▶ staging ──PR──▶ main ──tag──▶ vX.Y.Z ──manual approval──▶ release
                  (integration)   (released)     (inert)                    (artifacts)
```

| Branch / ref | Meaning |
|--------------|---------|
| `feature/*`, `fix/*` | Short-lived topic branches off `staging`. |
| `staging` | Integration branch. Everything lands here first; CI (fmt, clippy, test, `cargo audit`) must be green. |
| `main` | Released, stable. Only fast-forwarded from `staging` via PR, or hotfixes. Protected: PR required. |
| `vX.Y.Z` tag | Annotated, protected cut on `main`. It is inert until a reviewed workflow is manually dispatched from `main`. |

## Flow

1. `git switch staging && git pull && git switch -c feature/x`
2. PR `feature/x → staging`. CI runs; merge when green.
3. When a release is ready, PR `staging → main`.
4. Tag the merge commit on `main`: `git tag -a v0.1.0 -m "v0.1.0" && git push origin v0.1.0`.
   The tag publishes nothing. Manually dispatch the candidate workflow from the
   `main` ref; publication requires a separate exact confirmation, verified
   repository controls, and environment approval. Homebrew and GHCR remain
   separate reviewed flows and are never changed by the Core release workflow.
5. Follow the full candidate, publication, anonymous-acquisition, and optional
   container procedure in `RELEASING.md`.
6. **Hotfix:** branch off `main`, PR into `main`, tag a patch, then back-merge
   `main → staging` so the branches don't drift.

## Why a CLI keeps `staging` lightweight

`staging` exists for integration + symmetry with the site repo, not because the
binary "deploys" anywhere. Keep it short-lived in practice: merge to `main` and
tag often rather than letting `staging` diverge for weeks. Long-lived divergence
between `staging` and `main` is the one failure mode to avoid.
