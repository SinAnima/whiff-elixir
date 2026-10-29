# TradeWhiffer

Tiny example package showing how to register an external `Whiff.Extractor`
without hardcoding it into core `whiff`.

```elixir
{:ok, report} =
  Whiff.extract("sample.trade",
    extractors: [TradeWhiffer],
    mode: :fallback
  )
```
