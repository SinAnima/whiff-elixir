# Hex publish checklist (`whiff`)

Preferred path: **automated** via [`.github/workflows/release.yml`](../.github/workflows/release.yml).

## Automated release

1. Bump `@version` in `mix.exs` and add a `CHANGELOG.md` entry.
2. Commit on `main` (no remote write from agents unless asked).
3. Tag exactly `vX.Y.Z` matching `@version` (example: `v0.1.0`).
4. Push the tag: `git push origin v0.1.0` (or `git push origin main --tags`).
5. Workflow **Release**:
   - Builds precompiled NIFs for every configured native target
   - Attaches archives to the GitHub Release
   - Generates `checksum-Elixir.Whiff.Native.exs`
   - Dry-runs, then `mix hex.publish --yes`
6. Confirm Hex package + docs: https://hex.pm/packages/whiff

### Secrets / environment

| Name | Where | Purpose |
|---|---|---|
| `HEX_API_KEY` | Repo secret and/or Environment `hex-production` | Hex publish |
| Environment `hex-production` | GitHub → Settings → Environments | Optional approval gate before publish |

Manual dry-run without publishing: **Actions → Release → Run workflow** with `dry_run: true` (still builds NIFs if you use a tag; for dispatch-only, tag wait is skipped — prefer tagging for a real release).

## Preflight (still do these)

1. Hex package name `whiff` owned by the intended org/user.
2. Tag == `v` + `mix.exs` `@version`.
3. `CHANGELOG.md` complete for the version.
4. ADR pins accurate: Rust `whiff` **0.5.1**, Hex Rustler **`~> 0.38`**.
5. Native precompile targets match the release matrix:
   - `aarch64-apple-darwin`
   - `x86_64-apple-darwin`
   - `x86_64-unknown-linux-gnu`
   - `aarch64-unknown-linux-gnu`
   - `x86_64-pc-windows-msvc`

## Manual fallback (if CI cannot publish)

```bash
# After the NIF build job has attached assets to the GitHub Release:
rm -f checksum-Elixir.Whiff.Native.exs
WHIFF_BUILD=1 MIX_ENV=prod mix compile
mix rustler_precompiled.download Whiff.Native --all --print --no-config
mix clean
rm -rf native/whiff_native/target
MIX_ENV=prod mix compile --warnings-as-errors
MIX_ENV=prod mix hex.build --unpack
MIX_ENV=prod mix hex.publish   # intentional; requires HEX_API_KEY / login
```

## Post-publish

1. Smoke-install a fresh Mix app **without** a Rust toolchain; call `Whiff.extract/1`.
2. Smoke with `WHIFF_BUILD=1` (source-build fallback).
3. Release notes: link Hex + upstream `baoulo/whiff` 0.5.1; note musl deferred / Windows best-effort.
