# TradeWhiffer

Tiny example package showing how to register an external `Whiff.Extractor`
without hardcoding it into core `whiff`.

Depends on the parent project via `path: "../.."` (use `{:whiff, "~> 0.3.0"}` from Hex in a real app).

## Fallback Whiffer

```elixir
{:ok, report} =
  Whiff.extract("sample.trade",
    extractors: [TradeWhiffer],
    mode: :fallback
  )
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

Staging copies on the BEAM; Elixir plugins still see the original path/filename via `Whiff.Input`.
