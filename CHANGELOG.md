# Changelog

All notable changes to this project will be documented in this file.

## 0.4.0 — 2026-11-12

### Changed

- Upstream Rust `whiff` pin **0.6.0 → 0.8.0** (`common` feature only).
  Report schema id remains `whiff/1`; vendored `priv/schemas/whiff-1.schema.json`
  refreshed from upstream (1.0 baseline freeze; additive growth).
- NIF adapted for whiff 0.8 library API: `Hashes` / `Error` are
  `#[non_exhaustive]` — use `Hashes::default()` / `Hashes::NONE` and a
  wildcard error arm.
- Native `common` coverage grows with upstream 0.7–0.8 (fonts, markup,
  configs, many more source languages, package manifests, …). Specialist
  Cargo features (`games`, `geo`, `science`, `data`, `cad`, `forensics`)
  remain **disabled** in this package.

### Tests

- Expanded coverage for options validation, scratch error paths, plugin runner,
  privacy scrubbing, and report helpers; include limiter in coveralls.
- Coveralls minimum raised **70 → 90** (suite ~92%).

### Notes

- Tag `v0.4.0` so Release rebuilds precompiled NIFs and regenerates
  `checksum-Elixir.Whiff.Native.exs` for Hex.

## 0.3.0 — 2026-11-02

### Added

- Opt-in local scratch staging: `stage: :local` on `extract/2` and `llm/2`
  copies the file to a local directory on the BEAM **before** the DirtyCpu NIF
  opens it. Useful for large files on NFS or other high-latency mounts.
  - Per-call: `Whiff.extract(path, stage: :local)`
  - App config: `:scratch_dir` (default `System.tmp_dir!()/whiff-scratch`),
    `:scratch_max_bytes` (default 1 GiB; refuse staging above this size)
  - Staged copies keep the original basename under a unique job directory and
    are deleted after the call
- Application config `:native_max_concurrency` (default `8`) sets the native
  limiter cap at startup

### Fixed

- `Whiff.Limiter` fail-open after the wait budget no longer calls `release/0`
  without an acquire (which permanently undercounted in-flight NIF work).
  Acquire returns `:acquired | :bypassed`; only `:acquired` releases.
- Limiter saturation detection now uses an uncapped ETS increment; the previous
  threshold form never observed “over max”

### Docs

- README: Configuration section, slow-filesystem guidance, staging examples
- ADR 0001 amended for DirtyCpu path I/O + scratch escape hatch
- Hex publish checklist updated for `v0.3.0`

## 0.2.0 — 2026-10-31

### Changed

- Upstream Rust `whiff` pin **0.5.1 → 0.6.0** (`common` feature). Report schema
  remains `whiff/1`; Engine / limits / privacy / `llm_view` API compatible.
- Native coverage expands with upstream Stage 6: executables, bytecode, crypto,
  databases, Apple formats, binary serialisations (forensics still behind the
  optional `forensics` Cargo feature — not enabled in this package).

### Notes

- Re-tag as `v0.2.0` so Release rebuilds precompiled NIFs and regenerates
  `checksum-Elixir.Whiff.Native.exs` for Hex.

## 0.1.0 — 2026-10-29

### Added

- Elixir wrapper around Rust `whiff` 0.5.1 via Rustler (`whiff_native`).
- Public API: `extract/2`, `extract_binary/2`, `llm/2`, bang variants, `extract_many/2`.
- String-keyed `whiff/1` reports with `Whiff.Error` tagged results.
- First-class `Whiff.Extractor` and `Whiff.Analyzer` behaviours with
  `:fallback` / `:augment` / `:override` modes and deterministic merge.
- Profiles, hashes, privacy, limits validation with conservative caps.
- DirtyCpu NIFs, bounded native concurrency, plugin timeouts.
- Precompiled NIFs via RustlerPrecompiled (GitHub Release assets + Hex checksum).
- Docs, CI, release workflow, example `trade_whiffer` package, Stage 0 probe.
