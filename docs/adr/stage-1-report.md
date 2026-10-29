# Stage 1 report — Mix project, Rustler, native baseline

**Date:** 2026-10-28  
**Status:** Acceptance met

## Files

- `mix.exs`, `mix.lock`, `.formatter.exs`, `.gitignore`, `.tool-versions`
- `lib/whiff.ex`, `lib/whiff/native.ex`, `lib/whiff/error.ex`, `lib/whiff/input.ex`, `lib/whiff/report.ex`, plus scaffolding for registry/extractor/analyzer/merge
- `native/whiff_native/` — Cargo crate, DirtyCpu NIFs, `whiff` 0.5.1 (`common` only)
- `priv/schemas/whiff-1.schema.json`
- `test/` fixtures + baseline extract tests
- `LICENSE`, `CHANGELOG.md`

## API choices

- Internal `Whiff.Native` only; public surface on `Whiff`.
- NIF returns UTF-8 JSON via **`NewBinary`**; Elixir Jason → string-keyed maps.
- Extract NIFs: **`schedule = "DirtyCpu"`**.
- Hex Rustler **`~> 0.38`** (0.39 not on Hex yet); native `rustler = "0.38"`.
- No zero-copy claim for `extract_bytes`.

## Commands

- `WHIFF_BUILD=1 mix compile` — green
- `WHIFF_BUILD=1 mix test` — **35 tests, 0 failures** (full suite after later stages)

## Acceptance

Met: native build, fixture extract to map, DirtyCpu for heavy work.  
Debt: precompiled artifacts / checksums deferred to Stage 7 release CI.
