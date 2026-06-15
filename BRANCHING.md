# Branching & releases — promtect

Two long-lived branches plus version tags. A CLI's "production" is a **tagged
release** (binaries + Homebrew), not a server deploy — so `main` is the released
line and tags are the cut points.

```
feature/* ──PR──▶ staging ──PR──▶ main ──tag──▶ vX.Y.Z
                  (integration)   (released)     (release build)
```

| Branch / ref | Meaning |
|--------------|---------|
| `feature/*`, `fix/*` | Short-lived topic branches off `staging`. |
| `staging` | Integration branch. Everything lands here first; CI (fmt, clippy, test, `cargo audit`) must be green. |
| `main` | Released, stable. Only fast-forwarded from `staging` via PR, or hotfixes. Protected: PR required. |
| `vX.Y.Z` tag | Cut on `main`. Triggers the release workflow (macOS + Linux binaries, Homebrew tap bump). |

## Flow

1. `git switch staging && git pull && git switch -c feature/x`
2. PR `feature/x → staging`. CI runs; merge when green.
3. When a release is ready, PR `staging → main`.
4. Tag the merge commit on `main`: `git tag -a v0.1.0 -m "v0.1.0" && git push origin v0.1.0`.
   The release workflow builds and publishes from the tag.
5. **Hotfix:** branch off `main`, PR into `main`, tag a patch, then back-merge
   `main → staging` so the branches don't drift.

## Why a CLI keeps `staging` lightweight

`staging` exists for integration + symmetry with the site repo, not because the
binary "deploys" anywhere. Keep it short-lived in practice: merge to `main` and
tag often rather than letting `staging` diverge for weeks. Long-lived divergence
between `staging` and `main` is the one failure mode to avoid.
