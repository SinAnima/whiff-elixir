# TradeWhiffer

Example package that implements `Whiff.Extractor` for a proprietary `.trade`
text format. It depends on `whiff` like any other application and registers
its extractor per call; nothing in `whiff` refers to it.

This copy depends on the parent repository with `path: "../.."`. An
application would use `{:whiff, "~> 0.4.0"}` from Hex. The path dependency
also pulls the optional `:rustler` dependency so the NIF can be built from
source.

## Usage

```elixir
{:ok, report} = Whiff.extract("deal.trade", extractors: [TradeWhiffer])

report["format"]["example.trade"]
#=> %{"trade_id" => "T-1001", "currency" => "USD"}
```

The default `mode: :fallback` runs the extractor only when native whiff did
not cover the file. Upstream detects a `.trade` file as plain text by
heuristic, which does not count as coverage.

In-memory bytes work the same way:

```elixir
Whiff.extract_binary(bytes, name: "deal.trade", extractors: [TradeWhiffer])
```

A file that does not start with `TRADE/1` still returns `{:ok, report}`; the
failure is recorded in `report["diagnostics"]["extractors"]`.

## Files on a network share

```elixir
config :whiff, scratch_dir: "/var/cache/whiff"

Whiff.extract("/mnt/nfs/feeds/deal.trade", stage: :local, extractors: [TradeWhiffer])
```

The native step reads the local copy. The extractor receives a
`Whiff.Input` for the original path and reads at most 64 KiB of it.

## Test

```bash
mix deps.get
mix test
```

The tests use `test/fixtures/sample.trade` from the parent repository.
