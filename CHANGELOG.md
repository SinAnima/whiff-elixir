# Changelog

All notable changes to this project will be documented in this file.

## 0.4.0 — unreleased

### Changed

- Upstream Rust `whiff` pin 0.6.0 → 0.8.0 (`common` feature only). The report
  schema id remains `whiff/1`; `priv/schemas/whiff-1.schema.json` is refreshed
  from upstream.
- NIF adapted to the whiff 0.8 library API (`#[non_exhaustive]` `Hashes`,
  `Error`, `Limits`).
- Each public function now rejects options it does not use, for example
  `tokens:` on `extract/2` or `extractors:` on `llm/2`. Duplicate options and
  `name:` together with `filename:` are rejected.
- `extractors:` and `analyzers:` must name loaded modules that implement the
  behaviour; invalid modules return `:invalid_option` (also for app config).
- `override_fields:` accepts only dotted paths such as `"content.title"`.
- All nine `limits:` keys now have caps. `max_text_bytes` (64 MiB),
  `hash_max_bytes` (4 GiB), and `max_parse_bytes` (256 MiB) were uncapped.
  Zero is rejected for `max_read_bytes`, `max_decompressed_bytes`,
  `file_timeout_ms`, and `extractor_timeout_ms`.
- Native limiter: a GenServer semaphore replaces the ETS counter. Slots held
  by a process that exits are released. Waiters are served in order, and a
  call that waits longer than `:native_wait_ms` (default 60 s) returns
  `{:error, %Whiff.Error{reason: :overloaded}}` instead of running without a
  slot.
- `Whiff.Merge`:
  - `diagnostics` patches accept only `warnings`, prefixed with the plugin id.
  - Unknown top-level sections are rejected.
  - A value written by one plugin cannot be replaced by another plugin unless
    declared in `override_fields`.
  - `security.risks` entries can be appended (validated, `source` set to
    `"elixir:<id>"`); other existing `security` values are never replaced.
  - Patches are limited to 10,000 values and 1 MiB of strings in total.
  - Provenance entries use upstream's `"path" => "source"` string shape and
    cover only paths the patch wrote.
- `Whiff.Privacy` ports upstream's patterns, validity checks, and
  `[redacted:<kind>]` markers. Plain digit runs are no longer redacted as
  phone numbers. Patches with sensitive map keys are rejected.
- Plugin error messages no longer include returned values, thrown values, or
  exception messages; plugin-authored messages are scrubbed and truncated to
  256 bytes.
- `:fallback` extractors do not run when upstream reports the file as
  `"unreadable"`.
- `t:Whiff.Error.reason/0` is a closed set, now including `:overloaded`.
  `raise Whiff.Error, "message"` sets `reason: :native_error`.
- `Whiff.version/0` is read from `mix.exs` at compile time.

### Fixed

- A plugin that exits, is killed, or crashes a linked process no longer
  kills the caller. Plugins run unlinked and are killed if the caller exits.
- Non-bang functions no longer raise for non-UTF-8 paths or names,
  non-keyword option lists, or a native panic.
- `stage: :local` reports now describe the original file (`source.path`,
  filesystem times, inode, mode, owner ids) instead of the scratch copy, and
  errors name the original path.
- Scratch staging uses a 0700 root and random job directory names, refuses
  a root that is a symlink, owned by another user, or writable by others, and
  removes partial copies on failure.
- `extract_many/2` runs paths in unlinked tasks, keeps the path when a task
  exits, and has a per-path `:timeout` (default 300 s).
- `supports?/2` failures, invalid `id/0`/`version/0` values, and ids that
  collide with native extractor ids are recorded in diagnostics instead of
  being skipped silently.
- `Report.native_covered?/1` no longer checks a `"partial"` status that the
  schema does not define.

### Removed

- The unused `llm_bytes` NIF.

### Tests

- Golden reports from the pinned Rust crate (`test/fixtures/golden/`) are
  compared field by field, and every report is validated against the schema.
- New coverage for plugin containment, conflicts, privacy leaks through
  errors, non-UTF-8 input, symlinks, unreadable files, scratch security,
  limiter ownership and FIFO order, scheduler responsiveness, and large
  binaries. Native crate unit tests run with `cargo test`.
- Fixtures are committed once instead of regenerated on every run.

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

- Native limiter (Whiff.Limiter) fail-open after the wait budget no longer calls `release/0`
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
