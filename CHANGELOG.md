# Changelog

All notable changes to this project will be documented in this file.

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
