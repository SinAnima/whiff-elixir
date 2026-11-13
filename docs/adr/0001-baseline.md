# 0001 — Baseline and compatibility (Stage 0)

**Date:** 2026-10-28  
**Status:** Accepted  
**Amended:** 2026-11-12 (upstream 0.8.0, limiter, scratch staging, merge and privacy rules)  
**Upstream reviewed:** baoulo/whiff crate `0.8.0` (Stage 0 reviewed `0.5.1`)

## Pins

| Component | Version | Notes |
|---|---|---|
| Rust crate `whiff` | **0.8.0** exact | `default-features = false`, `features = ["common"]`; no `cli` |
| Report schema | `whiff/1` (`whiff::SCHEMA`) | Vendored at `priv/schemas/whiff-1.schema.json` (0.8 freezes 1.0 baseline) |
| Rust (NIF crate MSRV) | **1.91+** | Native crate `rust-version`; local probe toolchain 1.97.1 |
| Upstream whiff MSRV | 1.89 | Satisfied by NIF MSRV |
| Elixir | **1.18+** | Local: 1.18.4 |
| OTP | **26+** (target 27/28) | Local: OTP 28 |
| Rustler (Hex) | `~> 0.38` | **Pinned to Hex.** Rustler **0.39** is on crates.io but **not published to Hex** as of 2026-10-28; Elixir deps and `native/whiff_native` both use 0.38 |
| RustlerPrecompiled | `~> 0.10` | Stage 7 distribution; `force_build` in `:dev`/`:test` |
| Jason | `~> 1.4` | Decode native JSON to string-keyed maps |

## Native return path (DirtyCpu + NewBinary)

Extract / LLM NIFs are scheduled on **DirtyCpu**. After open/read, work is CPU-bound parsing/hashing; DirtyIo alone would still starve regular schedulers during extractors.

Path-based extract therefore performs file I/O on DirtyCpu threads. For large files on slow or network storage, callers may set `stage: :local` so Elixir copies the file to a private directory under `scratch_dir` before acquiring a native slot; the NIF then opens the copy. Afterwards the report's `source.path` and filesystem fields are rewritten from the original (second precision; fields Elixir cannot read are omitted and noted in `diagnostics.warnings`). Small in-memory payloads should use `extract_binary/2`. Auto-detecting slow mounts is out of scope.

Reports leave the NIF as UTF-8 JSON via Rustler **`NewBinary`** (owned BEAM binary). Elixir decodes with Jason into **string-keyed** maps — no uncontrolled atom keys.

## Verified upstream API facts (0.8.0 for this NIF)

- `Engine` is `Clone` / `Sync`; builder supports `profile`, `limits`, `hashes`, `only`, `skip`, `format`, `provenance`, `privacy`, `registry`, `options`, `build`.
- `Profile`: `Minimal`, `Standard` (default), `Full`, `Llm` (`#[non_exhaustive]`). Setting profile resets limits unless `limits` was set explicitly.
- `Hashes` (`#[non_exhaustive]`): use `Hashes::default()` / `Hashes::NONE` then set pub fields; do not construct with a struct literal from outside the crate.
- `Privacy::Strict` (default) / `Privacy::Off` (`#[non_exhaustive]`).
- `Limits` (`#[non_exhaustive]`): start from `profile.limits()` / `Default` and mutate or use setters.
- `Error` (`#[non_exhaustive]`): match `Io { … }` with a wildcard arm.
- `extract_path` → `Result<Report, Error>`; fails only when the path cannot be inspected. Extractor problems live in `diagnostics`.
- `extract_bytes(name, bytes: Into<Arc<[u8]>>)` → `Report` (infallible at API level).
- On `file_timeout` overrun: detection-only report, `diagnostics.limits_hit` includes `"timeout"`, worker thread may be abandoned.
- `Report::llm_view(max_tokens: usize) -> serde_json::Value`.
- Native plugins are Rust traits; Elixir cannot register into `Registry`. Internal modules (`formats`, `detect`, …) are no longer public as of 0.8.

## Platform matrix

| Target | Role |
|---|---|
| `x86_64-unknown-linux-gnu` (ubuntu-22.04) | **Mandatory CI** |
| `aarch64-apple-darwin` (macos-15; macos-14 runners were retired) | **Mandatory CI** |
| `x86_64-pc-windows-msvc` | Best-effort |
| Linux aarch64 glibc | Best-effort |
| musl / static | Not supported |

## Current limitations

1. Abandoned worker threads after native `file_timeout` may continue consuming CPU and memory; BEAM timeouts cannot stop them.
2. `extract_bytes` copies the BEAM binary once into `Arc<[u8]>`; there is no zero-copy path.
3. No Elixir callbacks inside native extraction or recursion into embedded children.
4. No streaming `extract_reader` NIF; inputs are a path or a binary.
5. `Whiff.Privacy` ports upstream's pattern list and markers for plugin patches but runs separately from the native privacy analyzer; structured personal-data handling (counting instead of listing) is native-only.

## Native concurrency

The native limiter (an internal GenServer) is a semaphore (`:native_max_concurrency`, default 8). Each holder is monitored, so a slot is released when its process exits for any reason. Waiters are served in FIFO order; a waiter that does not get a slot within `:native_wait_ms` (default 60 s) receives `:overloaded`. The earlier ETS counter leaked a slot whenever a holder was killed and bypassed the limit after its wait budget, which removed the bound under load.

## Plugin isolation

Plugin callbacks run in processes started with `spawn_monitor` (not linked). A guard process kills the plugin if the caller exits. Error messages record only the shape of a bad return value or the exception module, never plugin data.

## Probe

`probes/rust_extract` — `cargo run --manifest-path probes/rust_extract/Cargo.toml` extracts `fixtures/hello.txt`, prints report + `llm_view(800)`, probes missing path IO error, and `extract_bytes`.

## Fallback coverage signal

Use `diagnostics.extractors` / identification extractor metadata plus `identification.format`, not magic detection alone, to decide whether native covered the file for `:fallback` mode. Low-confidence heuristic hits without `extension_matches` are not treated as covered. A file upstream reports as `"unreadable"` (it exists but cannot be opened) never triggers a fallback.
