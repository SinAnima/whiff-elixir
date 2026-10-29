# Stage 2 report — Public API and errors

**Date:** 2026-10-28  
**Status:** Acceptance met

## Files

- `lib/whiff.ex` — `extract/2`, `extract!/2`, `extract_binary/2`, `extract_binary!/2`, `llm/2`, `llm!/2`, `version/0`, `schema_version/0`
- `lib/whiff/error.ex` — `defexception` with `:message`, `:reason`, `:path`, `:details`
- `lib/whiff/input.ex` — `:path` / `:binary` canonical input; presentation omits bytes
- `lib/whiff/options.ex` — option validation before native calls
- `test/whiff_test.exs`, `test/whiff/options_test.exs`

## API choices

- Non-bang → `{:ok, map}` | `{:error, %Whiff.Error{}}`; bang raises the same struct.
- Stable reasons: `:enoent`, `:eacces`, `:invalid_option`, `:unsupported_input`, `:native_error`, `:invalid_report`, `:extractor_error`, `:timeout`, …
- Unknown option names rejected; partial native reports with diagnostics stay `{:ok, report}`.
- `llm/2` uses upstream `llm_view`; default `tokens: 800`.

## Commands

- `WHIFF_BUILD=1 mix test` — **35/0**

## Acceptance

Met: typespecs/doctests, invalid-option coverage, consistent bang/non-bang errors.  
Debt: none blocking; OS permission fixtures remain environment-dependent.
