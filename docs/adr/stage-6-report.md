# Stage 6 report — OTP / concurrency / safety

**Date:** 2026-10-28  
**Status:** Acceptance met

## Files

- `lib/whiff/application.ex`, `lib/whiff/limiter.ex` — ETS-backed native concurrency bound (default 8)
- `Whiff.extract_many/2` — `Task.async_stream`, ordered results, `max_concurrency` / timeout opts
- Scheduler responsiveness test in `test/whiff_test.exs`; batch + plugin timeout in `plugin_test.exs`
- `config/config.exs`, `config/test.exs`

## API choices

- Sync extract remains free of GenServer bottlenecks; limiter only bounds concurrent NIF entries.
- Plugin work in monitored timed tasks; BEAM timeout ≠ native worker kill (documented).
- No default logging of paths/content/PII; avoid atoms from external strings.
- Telemetry omitted for v0.1 (no clear value without leak risk).

## Commands

- `WHIFF_BUILD=1 mix test` — **35/0**

## Acceptance

Met: concurrent extract responsiveness, bounded `extract_many`, plugin timeout containment.  
Debt: Port/subprocess isolation for adversarial formats deferred; abandoned native timeout threads remain an upstream limitation.
