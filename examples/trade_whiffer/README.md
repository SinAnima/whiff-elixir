# TradeWhiffer

Example Hex-style package that implements `Whiff.Extractor` for proprietary
`.trade` files without hardcoding into core `whiff`.

Depends on the parent project via `path: "../.."` (use `{:whiff, "~> 0.4.0"}`
from Hex in a real app). Path development also pulls optional `:rustler` so
local NIF source builds can compile.

## Fallback Whiffer

```elixir
{:ok, report} =
  Whiff.extract("sample.trade",
    extractors: [TradeWhiffer],
    mode: :fallback,
    hashes: :none
  )

get_in(report, ["format", "example.trade", "trade_id"])
```

## With local scratch (slow share)

If `.trade` files live on NFS, stage before the NIF:

```elixir
# config/config.exs
config :whiff,
  scratch_dir: "/var/cache/whiff",
  scratch_max_bytes: 64 * 1024 * 1024

{:ok, report} =
  Whiff.extract("/mnt/nfs/feeds/deal.trade",
    stage: :local,
    extractors: [TradeWhiffer],
    mode: :fallback,
    hashes: :none
  )
```

Staging copies on the BEAM; Elixir plugins still see the original path and
filename via `Whiff.Input`.

## Test

```bash
mix test
```

Uses `test/fixtures/sample.trade` from the parent project.
