# Hex publish checklist (`whiff`)

Preferred path: **automated** via [`.github/workflows/release.yml`](../.github/workflows/release.yml).

## Do precompiled NIFs ship with the release?

**Yes.** Tagging `v0.4.0` runs the Release workflow, which:

1. **Builds** precompiled `whiff_native` archives for each configured native target
2. **Attaches** those archives to the **GitHub Release**  
   `https://github.com/SinAnima/whiff-elixir/releases/download/v0.4.0/...`
3. **Generates** `checksum-Elixir.Whiff.Native.exs` and includes it in the **Hex** package
4. **Publishes** to Hex (`mix hex.publish --yes`)

| Artifact | Where it lives |
|---|---|
| `.so` / `.dll` NIF tarballs | GitHub Release assets (not inside the Hex tarball) |
| `checksum-Elixir.Whiff.Native.exs` | Hex package (required for verified download) |
| Native sources + `Cargo.lock` | Hex package (source-build fallback) |

Consumers without Rust download NIFs at compile time via RustlerPrecompiled.  
`WHIFF_BUILD=1` (or missing checksum) still force-builds from source.

### Targets built for v0.4.0

- `aarch64-apple-darwin`
- `x86_64-apple-darwin` (`macos-15-intel` runner)
- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu` (cross)
- `x86_64-pc-windows-msvc` (best-effort)

Musl is **not** in v0.4.0.

## Automated release (v0.4.0)

1. Finish / merge all intended commits on `main` (`@version` is already `"0.4.0"`).
2. Confirm secrets:
   - `HEX_API_KEY` (repo or Environment `hex-production`)
   - Environment `hex-production` created (approval gate recommended)
3. Tag exactly: `git tag v0.4.0`
4. Push tag: `git push origin v0.4.0` (and `main` if needed)
5. Watch **Actions → Release**:
   - `build_nifs` matrix succeeds
   - GitHub Release `v0.4.0` has **5** NIF assets
   - `publish_hex` generates checksum, dry-runs, publishes (under `MIX_ENV=dev` so `ex_doc` is available)
6. Confirm https://hex.pm/packages/whiff and HexDocs land on the README

### Secrets / environment

| Name | Where | Purpose |
|---|---|---|
| `HEX_API_KEY` | Repo secret and/or Environment `hex-production` | Hex publish |
| Environment `hex-production` | GitHub → Settings → Environments | Optional approval gate before publish |

## Preflight

1. Hex package name `whiff` owned by the intended org/user.
2. Tag == `v` + `mix.exs` `@version` → `v0.4.0`.
3. `CHANGELOG.md` entry for `0.4.0` is complete.
4. Pins: Rust `whiff` **0.8.0**, Hex Rustler **`~> 0.38`**, package **0.4.0**.
5. Do **not** commit `priv/native/*.so` or a hand-made checksum unless produced by the release job.
6. `mix package.files` includes `checksum-*.exs` and native sources; excludes built NIFs.

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
# Publish under MIX_ENV=dev so ex_doc (only: [:dev, :docs]) is available.
# Do NOT use MIX_ENV=prod for hex.publish — the docs task will be missing.
MIX_ENV=dev mix deps.get
MIX_ENV=dev mix hex.publish   # requires HEX_API_KEY / login
```

## Post-publish

1. Smoke-install a fresh Mix app **without** a Rust toolchain; call `Whiff.extract/1`.
2. Smoke with `WHIFF_BUILD=1` (source-build fallback).
3. Release notes: link Hex + upstream `baoulo/whiff` 0.8.0; note `common`-only feature set; musl deferred / Windows best-effort.
