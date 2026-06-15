# Releasing Promtect

Binaries and the Homebrew formula are driven by tags.

## Cut a release

1. Land everything on `main` (green CI) and bump `version` in `Cargo.toml`.
2. Tag and push:
   ```sh
   git tag -a vX.Y.Z -m "Promtect vX.Y.Z"
   git push origin vX.Y.Z
   ```
3. The **`release`** workflow (`.github/workflows/release.yml`) builds and attaches
   binaries to the GitHub Release for the tag:
   - macOS: `aarch64-apple-darwin`, `x86_64-apple-darwin`
   - Linux: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`
   - Each as `promtect-vX.Y.Z-<target>.tar.gz` + a `.sha256` sidecar.

## Update Homebrew

After the release assets exist, regenerate the formula from the published checksums
and push it to the tap:

```sh
scripts/update-formula.sh vX.Y.Z > ../homebrew-tap/Formula/promtect.rb
cd ../homebrew-tap && git commit -am "promtect vX.Y.Z" && git push
```

Install: `brew install Amitk3293/tap/promtect` (tap repo `Amitk3293/homebrew-tap`).

## Moving to a `promtect` org later

The repo can be transferred to an org without losing history, issues, PRs,
releases/binaries, or stars; old URLs redirect and your commit authorship is
preserved. After a transfer, repoint:
- this repo's `release.yml` runs unchanged (owner-relative),
- the brew line + `scripts/update-formula.sh` default repo (`PROMTECT_REPO`),
- the site's GitHub links and the formula `url`s,
- re-link Workers Builds and any CI secrets.
