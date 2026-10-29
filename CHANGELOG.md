# Changelog

All notable changes to this project will be documented in this file.

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
