# whiff

Elixir wrapper around the Rust [whiff](https://github.com/baoulo/whiff) crate (`0.5.1`).  
Sniff a file (or bytes) into a string-keyed **`whiff/1`** report, with first-class Elixir extractors (“Whiffers”) and analyzers.

## Requirements

| Piece | Version |
|---|---|
| Elixir | `~> 1.18` |
| OTP | 26+ (CI uses 27) |
| Rust (source / force build) | **1.91+** |
| Hex [Rustler](https://hex.pm/packages/rustler) | **`~> 0.38`** |

Rustler **0.39** exists on crates.io but is **not on Hex** as of 2026-10-28; this package pins **`~> 0.38`** on both the Elixir and native sides.

## Install

```elixir
def deps do
  [
    {:whiff, "~> 0.1.0"}
  ]
end
```

### Native NIF

- **Dev / test:** `RustlerPrecompiled` uses **`force_build`** (or set `WHIFF_BUILD=1`). A Rust toolchain is required locally.
- **Prod / Hex consumers:** precompiled artifacts from GitHub Releases. Tag `vX.Y.Z` runs [`.github/workflows/release.yml`](.github/workflows/release.yml): builds NIFs, attaches them to the release, generates **`checksum-Elixir.Whiff.Native.exs`**, and publishes to Hex (`HEX_API_KEY` + optional Environment `hex-production`).

## Unsupported / limited targets

| Target | Status |
|---|---|
| `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` | Mandatory CI |
| `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin` | Precompiled / best-effort |
| `x86_64-pc-windows-msvc` | **Best-effort** (CI `continue-on-error`) |
| **musl / static Linux** | **Deferred** (not v0.1) |

## Quick use

```elixir
{:ok, report} = Whiff.extract("report.pdf")
report["identification"]["format"]

{:ok, report} = Whiff.extract_binary(bytes, name: "image.jpg")
{:ok, compact} = Whiff.llm("report.pdf", tokens: 800)

{:ok, report} =
  Whiff.extract("position.trade",
    extractors: [MyBank.TradeWhiffer],
    mode: :fallback
  )
```

See `examples/trade_whiffer` for an external Whiffer package. Baseline decisions: [`docs/adr/0001-baseline.md`](docs/adr/0001-baseline.md). Hex release steps: [`docs/hex-publish-checklist.md`](docs/hex-publish-checklist.md).

## Limitations (v0.1)

- Native `file_timeout` may abandon worker threads; BEAM timeouts cannot kill them.
- No zero-copy guarantee for `extract_binary`.
- Elixir plugins run **outside** the NIF; privacy redaction on plugin patches is not claimed equivalent to upstream’s analyzer.
- No streaming `extract_reader` NIF.

## Develop

```bash
mix deps.get
WHIFF_BUILD=1 mix test
mix ci                               # compile, format, credo, doctor, test --cover, docs
cargo run --manifest-path probes/rust_extract/Cargo.toml
```

## License

MIT
