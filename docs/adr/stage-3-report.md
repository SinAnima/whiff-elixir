# Stage 3 report — Profiles, limits, fidelity

**Date:** 2026-10-28  
**Status:** Acceptance met

## Files

- `lib/whiff/options.ex` — profiles, hashes, privacy, only/skip/format/provenance, limits + caps
- `priv/schemas/whiff-1.schema.json` + `ex_json_schema` (test-only)
- Fixtures: `hello.txt`, `tiny.jpg`, `tiny.pdf`, `sample.zip`, `nested.zip`, `empty.bin`, `corrupt.pdf`, `café.txt`
- `test/whiff/fidelity_test.exs`

## API choices

- Profiles `:minimal | :standard | :full | :llm`; hashes `:all | :none | list`; privacy default `:strict`.
- Conservative limit caps (e.g. depth, timeout, read bytes) enforced in Elixir and mirrored in NIF.
- Preserve `whiff/1` keys; no undocumented native field mutation.
- Schema validation in tests against vendored schema.

## Commands

- `WHIFF_BUILD=1 mix test` — **35/0**

## Acceptance

Met: schema-validation + multi-format fidelity tests.  
Debt: full byte-identical golden vs Rust probe for every fixture not automated; nondeterministic fields (timing) excluded by design.
