# Stage 4 report — Elixir Whiffers

**Date:** 2026-10-28  
**Status:** Acceptance met

## Files

- `lib/whiff/extractor.ex` — behaviour (`id`, `version`, `supports?/2`, `extract/2`)
- `lib/whiff/registry.ex`, `lib/whiff/plugin.ex` — registration, modes, crash/timeout boundary
- `lib/whiff/merge.ex` — deterministic section merge
- `test/support/trade_whiffer.ex`, `test/fixtures/sample.trade`
- `test/whiff/plugin_test.exs` (fallback / augment / override / coverage)

## API choices

- Modes: `:fallback` (default), `:augment`, `:override` with explicit `override_fields`.
- Fallback only when native does **not** cover format (`Whiff.Report.native_covered?/1`); access errors do not fall back.
- Plugin failures default to diagnostics + `{:ok, report}`; `:strict` → error.
- `supports?` / `extract` raises caught at plugin boundary; `plugin_timeout_ms` via monitored tasks.
- No BEAM callbacks from inside the NIF.

## Commands

- `WHIFF_BUILD=1 mix test` — **35/0**

## Acceptance

Met: fallback/augment/override, crash/timeout, coverage bypass.  
Debt: heuristic coverage signal is conservative (may fall back more often than a human would prefer).
