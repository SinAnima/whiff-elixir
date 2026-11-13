defmodule TradeWhifferTest do
  use ExUnit.Case, async: false

  @fixture Path.expand("../../../test/fixtures/sample.trade", __DIR__)

  test "extracts proprietary .trade via fallback Whiffer" do
    assert File.exists?(@fixture)

    assert {:ok, report} =
             Whiff.extract(@fixture,
               extractors: [TradeWhiffer],
               mode: :fallback,
               hashes: :none
             )

    assert get_in(report, ["format", "example.trade", "trade_id"])
    assert get_in(report, ["content", "title"]) =~ "Trade"
  end
end
