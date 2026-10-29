# Stage 7 report — Distribution, docs, CI

**Date:** 2026-10-28  
**Status:** Acceptance met (publish deferred)

## Files

- `lib/whiff/native.ex` — `RustlerPrecompiled` + `force_build` for `:dev`/`:test` / `WHIFF_BUILD=1`
- `.github/workflows/ci.yml` — ubuntu-22.04 + macos-14 mandatory; Windows best-effort
- `examples/trade_whiffer/` — standalone path-dep Whiffer package
- `docs/adr/0001-baseline.md`, stage reports, `docs/hex-publish-checklist.md`
- `README.md`, `CHANGELOG.md`, ExDoc extras wiring in `mix.exs`
- Package files list includes `checksum-*.exs` (generated at release; not committed for local force_build)

## API choices

- Precompiled targets: aarch64/x86_64 apple-darwin, x86_64/aarch64 linux-gnu, x86_64 windows-msvc.
- **Unsupported / deferred:** musl/static; Windows is best-effort only.
- Hex package name `whiff`; do not publish until checklist + checksums ready.
- Release CI will generate `checksum-Elixir.Whiff.Native.exs`; local/dev uses `force_build`.

## Commands

- `WHIFF_BUILD=1 mix compile` / `mix test` — **35/0**
- `cargo run --manifest-path probes/rust_extract/Cargo.toml` — probe OK
- Hex publish — **not run** (see checklist)

## Acceptance

Met: CI, docs, example package, precompiled wiring with force_build fallback.  
Debt: no published Hex release yet; checksum file stub pending first release artifact job; musl deferred.
