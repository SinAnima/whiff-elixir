defmodule TradeWhifferTest do
  use ExUnit.Case, async: false

  doctest TradeWhiffer

  @fixture Path.expand("../../../test/fixtures/sample.trade", __DIR__)

  defp run(report),
    do: Enum.find(report["diagnostics"]["extractors"], &(&1["id"] == "example.trade"))

  test "extracts a .trade file through :fallback" do
    assert {:ok, report} = Whiff.extract(@fixture, extractors: [TradeWhiffer], hashes: :none)

    assert report["format"]["example.trade"] == %{"trade_id" => "T-1001", "currency" => "USD"}
    assert report["content"]["title"] == "Trade T-1001"
    assert %{"status" => "ok", "version" => 1} = run(report)
  end

  test "extracts in-memory bytes" do
    assert {:ok, report} =
             Whiff.extract_binary("TRADE/1\nid=T-2\ncurrency=GBP\n",
               name: "deal.trade",
               extractors: [TradeWhiffer],
               hashes: :none
             )

    assert report["format"]["example.trade"] == %{"trade_id" => "T-2", "currency" => "GBP"}
  end

  test "a malformed file is a report with an error diagnostic" do
    assert {:ok, report} =
             Whiff.extract_binary("not a trade\n",
               name: "bad.trade",
               extractors: [TradeWhiffer],
               hashes: :none
             )

    refute Map.has_key?(report["format"], "example.trade")
    assert %{"status" => "error", "error" => "not a TRADE/1 file"} = run(report)
  end

  test "works with stage: :local" do
    scratch = Path.join(System.tmp_dir!(), "trade-whiffer-#{System.unique_integer([:positive])}")
    Application.put_env(:whiff, :scratch_dir, scratch)

    try do
      assert {:ok, report} =
               Whiff.extract(@fixture, stage: :local, extractors: [TradeWhiffer], hashes: :none)

      assert report["source"]["path"] == @fixture
      assert report["format"]["example.trade"]["trade_id"] == "T-1001"
      assert File.ls!(scratch) == []
    after
      Application.delete_env(:whiff, :scratch_dir)
      File.rm_rf!(scratch)
    end
  end
end
