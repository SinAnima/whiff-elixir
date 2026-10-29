# Stage 5 report — Analyzers, merge, provenance/privacy

**Date:** 2026-10-28  
**Status:** Acceptance met

## Files

- `lib/whiff/analyzer.ex` — behaviour returning partial patches
- `lib/whiff/merge.ex` — protected security/integrity/diagnostics/embedded; namespaced `format`/`metadata`
- `lib/whiff/privacy.ex` — Elixir-side redaction under `:strict` for plugin patches
- `test/support/test_analyzers.ex`, privacy/secret fixtures in `plugin_test.exs`

## API choices

- Analyzers run after extractors; patches validated (no atom keys, no embedded rewrite, size bounds).
- Never erase native `security.*`, `integrity`, `diagnostics`, `embedded`.
- Plugin outcomes recorded in `diagnostics.extractors` shape (not a top-level `plugins` object).
- Documented: Elixir redaction ≠ upstream privacy analyzer equivalence.

## Commands

- `WHIFF_BUILD=1 mix test` — **35/0**

## Acceptance

Met: merge safety, secret redaction under strict privacy, analyzer fail/strict modes.  
Debt: provenance field-path recording is best-effort when native provenance is off; richer equivalence to upstream privacy not claimed.
